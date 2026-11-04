// Package inventory sends the inventory of an endpoint audit to SafeDep
// Cloud. The dry/cloud/endpointsync client keeps the events in a log in the
// state directory (decisions P11) until SafeDep Cloud confirms them, so an
// audit that cannot reach SafeDep Cloud sends its events on a later run.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/plugins/internal/grpcdial"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the plugin name, plugins.cloud-inventory.
const Name = "cloud-inventory"

// LogFile returns the name of the event log in the state directory for
// one SafeDep Cloud API and tenant. A switch of the tenant, as with
// --profile, must not send the waiting events of one tenant to another.
func LogFile(apiURL, tenant string) string {
	sum := sha256.Sum256([]byte(apiURL + "\n" + tenant))
	return "inventory-sync-" + hex.EncodeToString(sum[:6]) + ".db"
}

// oldLogFile is the log of the stub that came before the sync. Its batches
// lack the data that SafeDep Cloud needs, so the syncer deletes it.
const oldLogFile = "inventory-sync.wal"

// toolName names vet in the events and in the endpointsync client.
const toolName = "vet"

// drainTimeout bounds the wait for SafeDep Cloud at the end of an audit.
const drainTimeout = 30 * time.Second

// Options are the options of the syncer, plugins.cloud-inventory.options.
type Options struct {
	// EndpointID names the endpoint in SafeDep Cloud. Set it on a machine
	// that changes on each run, such as a CI runner. Empty uses the host
	// name and the machine id, as pmg does, so the tools of one machine
	// show as one endpoint.
	EndpointID string `json:"endpoint_id"`
}

// Decode decodes the options.
func Decode(cfg plugin.Config) (Options, error) {
	var o Options
	err := cfg.Decode(&o)
	return o, err
}

// OptionsSchema returns the JSON Schema of the options.
func (Options) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var _ plugin.Schemer = Options{}

// Client is the part of the endpointsync client that the syncer uses.
type Client interface {
	NewEvent() (*servicev1.ToolEvent, error)
	Emit(ctx context.Context, ev *servicev1.ToolEvent) error
	Sync(ctx context.Context) (int, error)
	Close() error
}

// Syncer sends the inventory of an audit.
type Syncer struct {
	client Client
	close  func() error
}

// New returns a syncer that sends its events with client.
func New(client Client) *Syncer { return &Syncer{client: client, close: client.Close} }

// Open connects to the SafeDep Cloud API at apiURL with the credentials of
// the run and opens the event log in stateDir.
func Open(o Options, apiURL string, creds *credentials.Result, stateDir, version string) (*Syncer, error) {
	key, err := creds.Credentials.GetAPIKey()
	if err != nil {
		return nil, err
	}
	id, err := endpointsync.NewEndpointIdentityResolver(endpointsync.WithEndpointID(o.EndpointID)).Resolve()
	if err != nil {
		// A container or a CI runner can have no machine id. The events of
		// the audit then never reach the log, so a retry cannot help.
		return nil, fmt.Errorf("vet could not name the endpoint (%v). Set plugins.cloud-inventory.options.endpoint_id to send the inventory", err)
	}
	if err := os.Remove(filepath.Join(stateDir, oldLogFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warnf("inventory sync: remove %s: %v", oldLogFile, err)
	}
	conn, err := grpcdial.Dial("vet-endpointsync", grpcdial.Endpoint{URL: apiURL, APIKey: key, Tenant: creds.TenantDomain()})
	if err != nil {
		return nil, err
	}
	logPath := filepath.Join(stateDir, LogFile(apiURL, creds.TenantDomain()))
	if err := privateFile(logPath); err != nil {
		return nil, errors.Join(fmt.Errorf("vet could not open the inventory sync log: %w", err), conn.Close())
	}
	client, err := endpointsync.NewSyncClient(toolName, version, endpointsync.NewGrpcTransport(conn), resolved{id},
		endpointsync.WithWALPath(logPath))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("vet could not open the inventory sync log: %w", err), conn.Close())
	}
	return &Syncer{client: client, close: func() error { return errors.Join(client.Close(), conn.Close()) }}, nil
}

// resolved gives the identity that Open resolved, so the client does not
// resolve it again and lose the hint on endpoint_id.
type resolved struct {
	id *controltowerv1pb.EndpointIdentity
}

func (r resolved) Resolve() (*controltowerv1pb.EndpointIdentity, error) { return r.id, nil }

// privateFile makes the log with mode 0600 before SQLite opens it, because
// the log holds the inventory of each user of the machine. SQLite gives
// its journal files the mode of the log. An older log gets the mode too.
func privateFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Close closes the event log and the connection.
func (s *Syncer) Close() error { return s.close() }

// Audit is what the syncer sends of one audit.
type Audit struct {
	// ScanID ties the events of one audit together.
	ScanID string
	Items  []report.InventoryItem
}

// Sync writes the events of an audit to the log, then sends the log. After
// an error of the send, the events wait in the log for the next run.
func (s *Syncer) Sync(ctx context.Context, a Audit) error {
	evs := events(a)
	var emitErrs []error
	for _, ev := range evs {
		if err := s.emit(ctx, a.ScanID, ev); err != nil {
			emitErrs = append(emitErrs, err)
		}
	}
	// vet sends the log also after a failed write. A full log refuses new
	// events, and only a send empties it.
	drain, cancel := context.WithTimeout(ctx, drainTimeout)
	defer cancel()
	sent, err := s.client.Sync(drain)
	var errs []error
	if emitErr := errors.Join(emitErrs...); emitErr != nil {
		errs = append(errs, fmt.Errorf("vet could not write %d of the %d events of the audit to the sync log (%w)", len(emitErrs), len(evs), emitErr))
	}
	switch {
	case err != nil:
		errs = append(errs, errors.New(unavailable(err)+". vet sends the inventory on the next audit"))
	case sent < len(evs)-len(emitErrs):
		// The client drops an event that SafeDep Cloud refuses, and keeps an
		// event over the quota for the next send. sent also counts the
		// events of earlier audits, so a shortfall can hide behind them.
		errs = append(errs, fmt.Errorf("SafeDep Cloud did not confirm %d of the %d events of the audit. vet sends the events that wait on the next audit. Run with --debug to see the reasons",
			len(evs)-len(emitErrs)-sent, len(evs)))
	}
	return errors.Join(errs...)
}

func (s *Syncer) emit(ctx context.Context, scanID string, ev event) error {
	te, err := s.client.NewEvent()
	if err != nil {
		return err
	}
	te.SetVetEvent(ev.vet)
	te.SetInvocationId(scanID)
	if ev.user != nil {
		te.SetInvocationContext(invocationContext(ev.user))
	}
	return s.client.Emit(ctx, te)
}

// unavailable explains a failed send. The API gateway answers a key that
// it refuses with a plain HTTP 401 or 403, which grpc-go reports as
// Unauthenticated, PermissionDenied, or Internal with no trailers behind
// some proxies. Without the hint the user sees a transport error and does
// not know to check the key.
func unavailable(err error) string {
	const base = "vet could not send the inventory to SafeDep Cloud"
	st, ok := status.FromError(err)
	if ok && (st.Code() == codes.Unauthenticated || st.Code() == codes.PermissionDenied ||
		st.Code() == codes.Internal && strings.Contains(st.Message(), "without sending trailers")) {
		return base + ". SafeDep Cloud refused the API key. Make sure that the key can sync endpoints and that it belongs to the tenant"
	}
	return fmt.Sprintf("%s (%v)", base, err)
}

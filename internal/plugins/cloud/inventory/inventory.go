// Package inventory syncs the inventory of an endpoint audit to SafeDep
// Cloud. It is a stub.
//
// gap G11: the endpoint inventory contract of safedep/api for vet v2 does
// not exist yet. Until it does, the syncer decodes its options, writes each
// batch to the write-ahead log in the state directory and returns
// plugin.ErrUnavailable. vet endpoint audit records a diagnostic and keeps
// its local report. The batches wait in the log for the contract.
package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the plugin name, plugins.cloud-inventory.
const Name = "cloud-inventory"

// Options are the options of the syncer, plugins.cloud-inventory.options.
type Options struct {
	// EndpointID names the endpoint in SafeDep Cloud. Empty uses the
	// target key of the audit, endpoint:<hostname>.
	EndpointID string `json:"endpoint_id"`
}

// Syncer sends the inventory items of an audit.
type Syncer struct {
	opts Options
	wal  *WAL
	now  func() time.Time
}

// New decodes the options. wal can be nil: the syncer then keeps no log.
func New(cfg plugin.Config, wal *WAL) (*Syncer, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	return &Syncer{opts: o, wal: wal, now: time.Now}, nil
}

// Sync writes the items of an audit of endpoint to the log, then sends
// the log. The stub sends nothing and returns plugin.ErrUnavailable.
func (s *Syncer) Sync(_ context.Context, endpoint string, items []report.InventoryItem) error {
	if s.opts.EndpointID != "" {
		endpoint = s.opts.EndpointID
	}
	if s.wal != nil {
		if err := s.wal.Append(Batch{At: s.now().UTC(), Endpoint: endpoint, Items: items}); err != nil {
			return fmt.Errorf("inventory log: %w", err)
		}
	}
	return fmt.Errorf("the SafeDep Cloud inventory sync is not available yet, so vet keeps the inventory in the local report: %w", plugin.ErrUnavailable)
}

// OptionsSchema returns the JSON Schema of the options.
func (*Syncer) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var _ plugin.Schemer = (*Syncer)(nil)

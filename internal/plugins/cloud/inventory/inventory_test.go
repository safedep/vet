package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	controltowerv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"buf.build/go/protovalidate"
	"github.com/safedep/dry/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

type fakeClient struct {
	emitted []*servicev1.ToolEvent
	syncErr error
	// refused is the number of events that SafeDep Cloud does not accept.
	refused int
	// emitErr fails each write to the log.
	emitErr error
	synced  bool
	closed  bool
}

func (f *fakeClient) NewEvent() (*servicev1.ToolEvent, error) {
	// The real client sets the same fields.
	return servicev1.ToolEvent_builder{
		EventId: "e", ToolName: "vet", ToolVersion: "test",
		Timestamp: timestamppb.New(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)),
	}.Build(), nil
}

func (f *fakeClient) Emit(_ context.Context, ev *servicev1.ToolEvent) error {
	if f.emitErr != nil {
		return f.emitErr
	}
	f.emitted = append(f.emitted, ev)
	return nil
}

func (f *fakeClient) Sync(context.Context) (int, error) {
	f.synced = true
	return len(f.emitted) - f.refused, f.syncErr
}

func (f *fakeClient) Close() error {
	f.closed = true
	return nil
}

func ptr[T any](v T) *T { return &v }

var alice = &report.InventoryUser{Name: "alice", UID: "501"}

// audit holds items of most types. The values are synthetic.
var audit = inventory.Audit{
	ScanID: "s-1",
	Items: []report.InventoryItem{
		{
			Kind: report.InventoryMCPServer, Type: report.InventoryTypeMCPServer, Name: "db", Client: "cursor",
			Path: "/home/alice/.cursor/mcp.json", Scope: "system", Identity: "i-db", Source: "s-cursor", User: alice,
			Enabled: ptr(true),
			MCPServer: &report.InventoryMCP{
				Transport: "stdio", Command: "node", Args: []string{"db.js", "--name", "a b"},
				EnvNames: []string{"DB_URL"}, HeaderNames: []string{"Authorization"}, AllowedTools: []string{"query"},
			},
		},
		{
			Kind: report.InventoryAITool, Type: report.InventoryTypeCodingAgent, Name: "Claude Code", Client: "claude_code",
			Version: "2.0.1", Path: "/home/alice/.claude/settings.json", Scope: "system", Identity: "i-cc", Source: "s-cc", User: alice,
			Agent: &report.InventoryAgent{PermissionMode: "default", Model: "opus", InstructionFiles: []string{"CLAUDE.md"}, APIKeyEnvName: "ANTHROPIC_API_KEY"},
		},
		{
			Kind: report.InventoryEditorPlugin, Type: report.InventoryTypeIDEExtension, Name: "ms-python.python", Client: "vscode",
			Version: "2023.20.0", Path: "/home/alice/.vscode/extensions/extensions.json", Scope: "system", Identity: "i-py", Source: "s-vs", User: alice,
			Extension: &report.InventoryExtension{IDE: "VS Code", Ecosystem: model.EcosystemVSCode, Package: "ms-python.python"},
		},
		{
			Kind: report.InventoryAITool, Type: report.InventoryTypeAIExtension, Name: "Copilot", Client: "vscode",
			Path: "/home/alice/.vscode/extensions/extensions.json", Scope: "system", Identity: "i-cp", Source: "s-vs", User: alice,
			Extension: &report.InventoryExtension{IDE: "VS Code"},
		},
		{
			Kind: report.InventoryAITool, Type: report.InventoryTypeCLITool, Name: "Gemini CLI", Client: "gemini_cli",
			Path: "/usr/local/bin/gemini", Scope: "system", Identity: "i-g", Source: "s-g", User: alice,
			Details: map[string]string{"binary.version": "0.9.0"},
		},
		{
			Kind: report.InventorySkill, Type: report.InventoryTypeSkill, Name: "review", Client: "claude_code",
			Path: "/work/app/.claude/skills/review/SKILL.md", Scope: "project", Identity: "i-r", Source: "s-r",
		},
		{Kind: report.InventoryAITool, Name: "a record of a repository scan has no type"},
	},
}

// TestEvents pins the events of an audit, and checks each one against the
// rules of the API contract, which control-tower applies too.
func TestEvents(t *testing.T) {
	c := &fakeClient{}
	require.NoError(t, inventory.New(c).Sync(context.Background(), audit))
	assert.True(t, c.synced)

	v, err := protovalidate.New()
	require.NoError(t, err)
	var got []any
	for _, ev := range c.emitted {
		require.NoError(t, v.Validate(ev), "the event obeys the API contract")
		assert.Equal(t, "s-1", ev.GetInvocationId())
		b, err := protojson.Marshal(ev)
		require.NoError(t, err)
		var m any
		require.NoError(t, json.Unmarshal(b, &m))
		got = append(got, m)
	}
	golden.AssertJSON(t, filepath.Join("testdata", "events.golden"), got)
}

func TestSyncFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"refused key", status.Error(codes.Unauthenticated, "no"), "SafeDep Cloud refused the API key"},
		{"gateway answer without trailers", status.Error(codes.Internal, "server closed the stream without sending trailers"), "SafeDep Cloud refused the API key"},
		{"network", errors.New("connection refused"), "connection refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inventory.New(&fakeClient{syncErr: tc.err}).Sync(context.Background(), audit)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), "next audit")
		})
	}
}

func TestSyncReportsRefusedEvents(t *testing.T) {
	err := inventory.New(&fakeClient{refused: 2}).Sync(context.Background(), audit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SafeDep Cloud did not confirm 2 of the 7 events")
}

// TestSyncSendsTheLogAfterAFailedWrite guards a full log: only a send
// empties it, so a failed write must not skip the send.
func TestSyncSendsTheLogAfterAFailedWrite(t *testing.T) {
	c := &fakeClient{emitErr: errors.New("log is full")}
	err := inventory.New(c).Sync(context.Background(), audit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not write 7 of the 7 events")
	assert.True(t, c.synced, "vet sends the log after a failed write")
}

// TestEachTypeHasAKind fails when a new inventory type has no kind of the
// API contract, so the sync would skip its items.
func TestEachTypeHasAKind(t *testing.T) {
	v, err := protovalidate.New()
	require.NoError(t, err)
	for _, typ := range report.InventoryTypes() {
		t.Run(string(typ), func(t *testing.T) {
			c := &fakeClient{}
			a := inventory.Audit{ScanID: "s", Items: []report.InventoryItem{{Type: typ, Name: "x", Scope: "system", Identity: "i"}}}
			require.NoError(t, inventory.New(c).Sync(context.Background(), a))
			require.Len(t, c.emitted, 2, "an item event and the summary")
			item := c.emitted[0].GetVetEvent().GetItemObserved()
			assert.NotEqual(t, controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_UNSPECIFIED, item.GetKind())
			assert.NoError(t, v.Validate(c.emitted[0]), "an item with no detail data still obeys the API contract")
		})
	}
}

func TestDecode(t *testing.T) {
	o, err := inventory.Decode(plugin.MapConfig(map[string]any{"endpoint_id": "ci-runner-1"}))
	require.NoError(t, err)
	assert.Equal(t, "ci-runner-1", o.EndpointID)

	_, err = inventory.Decode(plugin.MapConfig(map[string]any{"wal": "x"}))
	assert.Error(t, err, "an unknown option is an error")

	var schema map[string]any
	require.NoError(t, json.Unmarshal(o.OptionsSchema(), &schema))
	assert.Contains(t, schema["properties"], "endpoint_id")
}

type endpointServer struct {
	controltowerv1grpc.UnimplementedEndpointServiceServer
	mu     sync.Mutex
	events []*servicev1.ToolEvent
}

func (e *endpointServer) SyncEvents(_ context.Context, req *servicev1.SyncEventsRequest) (*servicev1.SyncEventsResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ids := make([]string, 0, len(req.GetEvents()))
	for _, ev := range req.GetEvents() {
		ids = append(ids, ev.GetEventId())
		e.events = append(e.events, ev)
	}
	return servicev1.SyncEventsResponse_builder{ConfirmedEventIds: ids}.Build(), nil
}

// TestOpenSendsThroughTheRealClient runs the endpointsync client against a
// local server: the log of each tenant, its mode, and the removal of the
// log of the stub that came before the sync.
func TestOpenSendsThroughTheRealClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	es := &endpointServer{}
	controltowerv1grpc.RegisterEndpointServiceServer(srv, es)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Log("serve:", err)
		}
	}()
	t.Cleanup(srv.Stop)
	apiURL := "http://" + ln.Addr().String()

	state := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(state, "inventory-sync.wal"), []byte("{}\n"), 0o600))
	cred, err := cloud.NewAPIKeyCredential("sk_test", "acme.safedep.io")
	require.NoError(t, err)

	s, err := inventory.Open(inventory.Options{EndpointID: "ci-runner-1"}, apiURL, &credentials.Result{Credentials: cred}, state, "test")
	require.NoError(t, err)
	require.NoError(t, s.Sync(context.Background(), inventory.Audit{ScanID: "s-1", Items: audit.Items[:1]}))
	logPath := filepath.Join(state, inventory.LogFile(apiURL, "acme.safedep.io"))
	if runtime.GOOS != "windows" {
		// The endpointsync log runs in WAL mode. SQLite removes the journal
		// files on a clean close, so the check runs while the log is open.
		for _, side := range []string{"-wal", "-shm"} {
			info, err := os.Stat(logPath + side)
			require.NoError(t, err, "the journal file %s exists while the log is open", side)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the journal file %s has the mode of the log", side)
		}
	}
	require.NoError(t, s.Close())

	es.mu.Lock()
	got := append([]*servicev1.ToolEvent(nil), es.events...)
	es.mu.Unlock()
	require.Len(t, got, 2, "the item and the summary")
	assert.Equal(t, "s-1", got[0].GetInvocationId())
	assert.NoFileExists(t, filepath.Join(state, "inventory-sync.wal"))
	info, err := os.Stat(logPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the log holds the inventory of each user")
	}
	assert.NotEqual(t, inventory.LogFile(apiURL, "acme.safedep.io"), inventory.LogFile(apiURL, "other.safedep.io"),
		"each tenant has its own log")
}

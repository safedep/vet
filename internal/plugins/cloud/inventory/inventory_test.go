package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"buf.build/go/protovalidate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

type fakeClient struct {
	emitted []*servicev1.ToolEvent
	syncErr error
	synced  bool
	closed  bool
}

func (f *fakeClient) NewEvent() (*servicev1.ToolEvent, error) {
	return servicev1.ToolEvent_builder{EventId: "e", ToolName: "vet", ToolVersion: "test"}.Build(), nil
}

func (f *fakeClient) Emit(_ context.Context, ev *servicev1.ToolEvent) error {
	f.emitted = append(f.emitted, ev)
	return nil
}

func (f *fakeClient) Sync(context.Context) (int, error) {
	f.synced = true
	return len(f.emitted), f.syncErr
}

func (f *fakeClient) Close() error {
	f.closed = true
	return nil
}

func ptr[T any](v T) *T { return &v }

var alice = &report.InventoryUser{Name: "alice", UID: "501"}

// audit holds one item of each type and a diagnostic. The values are
// synthetic.
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
	Diagnostics: []report.Diagnostic{
		{Level: report.DiagnosticWarning, Code: "endpoint_unreadable", Component: "endpoint", Message: "vet could not read a folder"},
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
		require.NoError(t, v.Validate(ev.GetVetEvent()), "the event obeys the API contract")
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
			c := &fakeClient{syncErr: tc.err}
			err := inventory.New(c).Sync(context.Background(), audit)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotEmpty(t, c.emitted, "the events stay in the log for the next run")
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

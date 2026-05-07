package local

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/inventory"
)

// twoSampleItems returns a small fixture covering an MCP server and a
// CLI tool — the two kinds with the most distinctive DETAIL column
// rendering, so a single set covers most table-render assertions.
func twoSampleItems() []*inventory.Item {
	return []*inventory.Item{
		{
			Kind:         inventory.KindMCPServer,
			ItemIdentity: "abc",
			SourceID:     "src",
			Name:         "anthropic-mcp",
			App:          "claude_code",
			Scope:        inventory.ScopeProject,
			ConfigPath:   "/work/.mcp.json",
			MCPServer: &inventory.MCPServerDetail{
				Transport: inventory.TransportStdio,
				Command:   "npx",
				Args:      []string{"-y", "@anthropic/mcp"},
			},
			Metadata: map[string]string{
				metaKeyAppDisplay: "Claude Code",
			},
		},
		{
			Kind:         inventory.KindCLITool,
			ItemIdentity: "def",
			SourceID:     "src2",
			Name:         "claude",
			App:          "claude_code",
			Scope:        inventory.ScopeSystem,
			ConfigPath:   "/usr/local/bin/claude",
			Metadata: map[string]string{
				metaKeyAppDisplay:    "Claude Code",
				metaKeyBinaryPath:    "/usr/local/bin/claude",
				metaKeyBinaryVersion: "1.2.3",
			},
		},
	}
}

func runScan(t *testing.T, sink *LocalSink, items []*inventory.Item) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, sink.Begin(ctx, inventory.NewSession()))
	for _, it := range items {
		require.NoError(t, sink.Emit(ctx, it))
	}
	require.NoError(t, sink.End(ctx, &inventory.ScanSummary{
		TotalObserved: uint64(len(items)),
	}))
}

func TestLocalSinkRendersTable(t *testing.T) {
	var buf bytes.Buffer
	sink := New(WithOutput(&buf))

	runScan(t, sink, twoSampleItems())

	out := buf.String()
	assert.Contains(t, out, "Discovered 2 AI tool usage(s)")
	assert.Contains(t, out, "TYPE")
	assert.Contains(t, out, "MCP Server")
	assert.Contains(t, out, "CLI Tool")
	assert.Contains(t, out, "anthropic-mcp")
	assert.Contains(t, out, "claude")
	assert.Contains(t, out, "Claude Code")
	assert.Contains(t, out, "stdio: npx")
	assert.Contains(t, out, "/usr/local/bin/claude v1.2.3")
}

func TestLocalSinkSilentSuppressesTable(t *testing.T) {
	var buf bytes.Buffer
	sink := New(WithOutput(&buf), WithSilent())

	runScan(t, sink, twoSampleItems())

	assert.Empty(t, buf.String(), "WithSilent must suppress all rendered output")
}

func TestLocalSinkEmptyScanRendersHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	sink := New(WithOutput(&buf))

	runScan(t, sink, nil)

	out := buf.String()
	assert.Contains(t, out, "Discovered 0 AI tool usage(s) across 0 app(s)")
	assert.NotContains(t, out, "TYPE", "no table when there are no items")
}

func TestLocalSinkWithReportJSONWritesItems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	sink := New(WithSilent(), WithReportJSON(path))
	items := twoSampleItems()
	runScan(t, sink, items)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var decoded []*inventory.Item
	require.NoError(t, json.Unmarshal(data, &decoded), "report file must be valid JSON")
	require.Len(t, decoded, len(items))
	assert.Equal(t, "anthropic-mcp", decoded[0].Name)
	assert.Equal(t, "claude", decoded[1].Name)
}

func TestLocalSinkBeginResetsBuffer(t *testing.T) {
	sink := New(WithSilent())
	ctx := context.Background()

	require.NoError(t, sink.Begin(ctx, inventory.NewSession()))
	require.NoError(t, sink.Emit(ctx, twoSampleItems()[0]))
	require.Len(t, sink.Items(), 1)

	// A second Begin must clear stale state from the prior scan.
	require.NoError(t, sink.Begin(ctx, inventory.NewSession()))
	assert.Empty(t, sink.Items())
}

func TestLocalSinkCloseClearsItems(t *testing.T) {
	sink := New(WithSilent())
	ctx := context.Background()
	runScan(t, sink, twoSampleItems())
	require.NoError(t, sink.Close(ctx))
	assert.Nil(t, sink.Items())
}

func TestItemDetailMCPWithURL(t *testing.T) {
	item := &inventory.Item{
		Kind: inventory.KindMCPServer,
		MCPServer: &inventory.MCPServerDetail{
			Transport: inventory.TransportSSE,
			URL:       "https://mcp.example.com",
		},
	}
	assert.Equal(t, "sse: https://mcp.example.com", itemDetail(item))
}

func TestItemDetailMCPMissingDetailFallsBackToConfigPath(t *testing.T) {
	item := &inventory.Item{
		Kind:       inventory.KindMCPServer,
		ConfigPath: "/etc/mcp.json",
	}
	assert.Equal(t, "/etc/mcp.json", itemDetail(item))
}

func TestItemDetailAIExtension(t *testing.T) {
	item := &inventory.Item{
		Kind: inventory.KindAIExtension,
		Metadata: map[string]string{
			metaKeyExtensionID:      "github.copilot",
			metaKeyExtensionVersion: "1.234",
			metaKeyExtensionIDE:     "VS Code",
		},
	}
	assert.Equal(t, "github.copilot v1.234 (VS Code)", itemDetail(item))
}

func TestItemDetailProjectConfigJoinsInstructionBaseNames(t *testing.T) {
	item := &inventory.Item{
		Kind: inventory.KindProjectConfig,
		Agent: &inventory.AgentDetail{
			InstructionFiles: []string{"/work/CLAUDE.md", "/work/AGENTS.md"},
		},
	}
	assert.Equal(t, "CLAUDE.md, AGENTS.md", itemDetail(item))
}

func TestItemDetailUnknownKindReturnsConfigPath(t *testing.T) {
	item := &inventory.Item{
		Kind:       inventory.KindBrowserExtension,
		ConfigPath: "/x/y",
	}
	assert.Equal(t, "/x/y", itemDetail(item))
}

func TestAppDisplayPrefersMetadata(t *testing.T) {
	item := &inventory.Item{App: "vscode", Metadata: map[string]string{metaKeyAppDisplay: "VS Code"}}
	assert.Equal(t, "VS Code", appDisplay(item))
}

func TestAppDisplayFallsBackToCanonicalApp(t *testing.T) {
	item := &inventory.Item{App: "vscode"}
	assert.Equal(t, "vscode", appDisplay(item))
}

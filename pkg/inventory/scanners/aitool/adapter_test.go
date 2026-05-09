package aitool

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/aitool"
	"github.com/safedep/vet/pkg/inventory"
)

// fakeReader is a minimal aitool.AIToolReader used to seed a registry
// with deterministic AITool emissions.
type fakeReader struct {
	tools []*aitool.AITool
	err   error
}

func (f *fakeReader) Name() string { return "fake" }
func (f *fakeReader) App() string  { return "fake_app" }
func (f *fakeReader) EnumTools(ctx context.Context, handler aitool.AIToolHandlerFn) error {
	if f.err != nil {
		return f.err
	}
	for _, t := range f.tools {
		if err := handler(t); err != nil {
			return err
		}
	}
	return nil
}

func newRegistryWithReader(reader aitool.AIToolReader) *aitool.Registry {
	r := aitool.NewRegistry()
	r.Register("fake", func(_ aitool.DiscoveryConfig) (aitool.AIToolReader, error) {
		return reader, nil
	})
	return r
}

// newRegistryRecordingConfig builds a registry whose factory writes the
// DiscoveryConfig into the supplied pointer when invoked.
func newRegistryRecordingConfig(captured *aitool.DiscoveryConfig) *aitool.Registry {
	r := aitool.NewRegistry()
	r.Register("recording", func(cfg aitool.DiscoveryConfig) (aitool.AIToolReader, error) {
		*captured = cfg
		return &recordingReader{}, nil
	})
	return r
}

func TestAdapterName(t *testing.T) {
	scanner := New(aitool.NewRegistry())
	assert.Equal(t, "aitool", scanner.Name())
}

func TestNewPanicsOnNilRegistry(t *testing.T) {
	assert.Panics(t, func() { New(nil) })
}

func TestAdapterScanEmitsTranslatedItems(t *testing.T) {
	reader := &fakeReader{
		tools: []*aitool.AITool{
			{
				Name:       "anthropic-mcp",
				Type:       aitool.AIToolTypeMCPServer,
				Scope:      aitool.AIToolScopeProject,
				App:        "claude_code",
				AppDisplay: "Claude Code",
				ConfigPath: "/work/.mcp.json",
				MCPServer: &aitool.MCPServerConfig{
					Transport: aitool.MCPTransportStdio,
					Command:   "npx",
				},
			},
			{
				Name:       "claude",
				Type:       aitool.AIToolTypeCLITool,
				Scope:      aitool.AIToolScopeSystem,
				App:        "claude_code",
				ConfigPath: "/usr/local/bin/claude",
				Metadata: map[string]any{
					metaKeyBinaryPath:    "/usr/local/bin/claude",
					metaKeyBinaryVersion: "1.0.0",
				},
			},
		},
	}

	scanner := New(newRegistryWithReader(reader))

	var emitted []*inventory.Item
	err := scanner.Scan(context.Background(), inventory.ScanConfig{
		HomeDir:    "/home/u",
		ProjectDir: "/work",
	}, func(item *inventory.Item) error {
		emitted = append(emitted, item)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, emitted, 2)

	assert.Equal(t, inventory.KindMCPServer, emitted[0].Kind)
	assert.Equal(t, "anthropic-mcp", emitted[0].Name)
	require.NotNil(t, emitted[0].MCPServer)
	assert.Equal(t, "npx", emitted[0].MCPServer.Command)

	assert.Equal(t, inventory.KindCLITool, emitted[1].Kind)
	assert.Equal(t, "/usr/local/bin/claude", emitted[1].Metadata[metaKeyBinaryPath])
}

func TestAdapterScanPropagatesEmitError(t *testing.T) {
	reader := &fakeReader{
		tools: []*aitool.AITool{
			{Name: "a", Type: aitool.AIToolTypeMCPServer, App: "x", ConfigPath: "/a"},
			{Name: "b", Type: aitool.AIToolTypeMCPServer, App: "x", ConfigPath: "/b"},
		},
	}
	scanner := New(newRegistryWithReader(reader))

	stop := errors.New("emit aborted")
	count := 0
	err := scanner.Scan(context.Background(), inventory.ScanConfig{}, func(*inventory.Item) error {
		count++
		return stop
	})
	require.ErrorIs(t, err, stop)
	assert.Equal(t, 1, count, "emit error must stop the scan immediately")
}

func TestAdapterScanRejectsNilEmit(t *testing.T) {
	scanner := New(aitool.NewRegistry())
	err := scanner.Scan(context.Background(), inventory.ScanConfig{}, nil)
	require.Error(t, err)
}

func TestAdapterScanWithNilScopesPassesAllScopes(t *testing.T) {
	var captured aitool.DiscoveryConfig
	scanner := New(newRegistryRecordingConfig(&captured))

	require.NoError(t, scanner.Scan(context.Background(), inventory.ScanConfig{
		HomeDir: "/h", ProjectDir: "/p",
	}, func(*inventory.Item) error { return nil }))

	assert.Equal(t, "/h", captured.HomeDir)
	assert.Equal(t, "/p", captured.ProjectDir)
	assert.Nil(t, captured.Scope, "nil inventory scopes must yield nil DiscoveryScope (all enabled)")
}

func TestAdapterScanWithExplicitScopesBuildsDiscoveryScope(t *testing.T) {
	var captured aitool.DiscoveryConfig
	scanner := New(newRegistryRecordingConfig(&captured))

	require.NoError(t, scanner.Scan(context.Background(), inventory.ScanConfig{
		HomeDir: "/h",
		Scopes:  []inventory.Scope{inventory.ScopeSystem},
	}, func(*inventory.Item) error { return nil }))

	require.NotNil(t, captured.Scope)
	assert.True(t, captured.Scope.IsEnabled(aitool.AIToolScopeSystem))
	assert.False(t, captured.Scope.IsEnabled(aitool.AIToolScopeProject))
}

func TestAdapterScanWithUnknownScopeReturnsError(t *testing.T) {
	scanner := New(aitool.NewRegistry())
	err := scanner.Scan(context.Background(), inventory.ScanConfig{
		Scopes: []inventory.Scope{inventory.Scope(99)},
	}, func(*inventory.Item) error { return nil })
	require.Error(t, err)
}

func TestAdapterScanSkipsNilTool(t *testing.T) {
	reader := &fakeReader{tools: []*aitool.AITool{nil, {
		Name: "x", Type: aitool.AIToolTypeMCPServer, App: "a", ConfigPath: "/p",
	}}}
	scanner := New(newRegistryWithReader(reader))

	count := 0
	err := scanner.Scan(context.Background(), inventory.ScanConfig{}, func(*inventory.Item) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count, "nil AITool must be skipped, not translated")
}

// recordingReader is a no-op AIToolReader used purely to satisfy the
// registry contract while the test asserts on the DiscoveryConfig that
// the adapter built.
type recordingReader struct{}

func (r *recordingReader) Name() string { return "recording" }
func (r *recordingReader) App() string  { return "rec" }
func (r *recordingReader) EnumTools(_ context.Context, _ aitool.AIToolHandlerFn) error {
	return nil
}

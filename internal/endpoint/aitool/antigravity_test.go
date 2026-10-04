package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

func TestAntigravityDiscoverer_WithFixtures(t *testing.T) {
	fixtures := fixturesDir(t)
	tmpDir := t.TempDir()

	err := copyDir(
		filepath.Join(fixtures, "antigravity-gemini"),
		filepath.Join(tmpDir, ".gemini", "antigravity"),
	)
	require.NoError(t, err)

	err = mkdir(filepath.Join(tmpDir, ".antigravity"))
	require.NoError(t, err)

	reader, err := NewAntigravityDiscoverer(DiscoveryConfig{HomeDir: tmpDir})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tools)

	var systemMCP []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindMCPServer && tool.Scope == inventory.ScopeSystem {
			systemMCP = append(systemMCP, tool)
		}
	}
	require.NotEmpty(t, systemMCP)
	assert.Equal(t, "ag-server", systemMCP[0].Name)
	assert.Equal(t, antigravityApp, systemMCP[0].App)
	assert.Equal(t, inventory.TransportStreamableHTTP, systemMCP[0].MCPServer.Transport)

	var agents []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindCodingAgent {
			agents = append(agents, tool)
		}
	}
	require.Len(t, agents, 1)
	assert.Equal(t, "Antigravity", agents[0].Name)
	assert.Equal(t, antigravityApp, agents[0].App)
	assert.Equal(t, inventory.ScopeSystem, agents[0].Scope)
}

func TestAntigravityDiscoverer_MissingConfig(t *testing.T) {
	reader, err := NewAntigravityDiscoverer(DiscoveryConfig{HomeDir: t.TempDir()})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err)
	assert.Empty(t, tools)
}

func TestAntigravityDiscoverer_DirExistsButNoMCPJson(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, mkdir(filepath.Join(tmpDir, ".antigravity")))

	reader, err := NewAntigravityDiscoverer(DiscoveryConfig{HomeDir: tmpDir})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, inventory.KindCodingAgent, tools[0].Kind)
	assert.Equal(t, "Antigravity", tools[0].Name)
}

func TestAntigravityDiscoverer_NoDuplicateCodingAgent(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, mkdir(filepath.Join(tmpDir, ".antigravity")))
	require.NoError(t, mkdir(filepath.Join(tmpDir, ".config", "Antigravity")))

	reader, err := NewAntigravityDiscoverer(DiscoveryConfig{HomeDir: tmpDir})
	require.NoError(t, err)

	var agents []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		if tool.Kind == inventory.KindCodingAgent {
			agents = append(agents, tool)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, agents, 1, "should emit only one coding_agent even when multiple dirs exist")
}

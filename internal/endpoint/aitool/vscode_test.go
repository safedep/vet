package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

func TestVSCodeDiscoverer_WithFixtures(t *testing.T) {
	fixtures := fixturesDir(t)
	tmpHome := t.TempDir()
	tmpProject := t.TempDir()

	// System MCP lives in the VS Code user-data dir, not ~/.vscode/.
	// Create ~/.vscode/ only for coding_agent detection; copy mcp.json to
	// the Linux user-data path the discoverer actually checks.
	require.NoError(t, mkdir(filepath.Join(tmpHome, ".vscode")))
	require.NoError(t, mkdir(filepath.Join(tmpHome, ".config", "Code", "User")))
	require.NoError(t, copyFile(
		filepath.Join(fixtures, "vscode", "mcp.json"),
		filepath.Join(tmpHome, ".config", "Code", "User", "mcp.json"),
	))

	// fixtures/vscode-project/mcp.json is stored outside a hidden dir to
	// avoid .gitignore exclusion; copy it into .vscode/ inside a temp dir.
	require.NoError(t, mkdir(filepath.Join(tmpProject, ".vscode")))
	require.NoError(t, copyFile(
		filepath.Join(fixtures, "vscode-project", "mcp.json"),
		filepath.Join(tmpProject, ".vscode", "mcp.json"),
	))

	reader, err := NewVSCodeDiscoverer(DiscoveryConfig{
		HomeDir:    tmpHome,
		ProjectDir: tmpProject,
	})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tools)

	var agents []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindCodingAgent {
			agents = append(agents, tool)
		}
	}
	require.Len(t, agents, 1)
	assert.Equal(t, "VS Code", agents[0].Name)
	assert.Equal(t, vscodeApp, agents[0].App)
	assert.Equal(t, inventory.ScopeSystem, agents[0].Scope)

	var systemMCP []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindMCPServer && tool.Scope == inventory.ScopeSystem {
			systemMCP = append(systemMCP, tool)
		}
	}
	require.NotEmpty(t, systemMCP)
	assert.Equal(t, "vscode-global", systemMCP[0].Name)
	assert.Equal(t, vscodeApp, systemMCP[0].App)

	var projectMCP []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindMCPServer && tool.Scope == inventory.ScopeProject {
			projectMCP = append(projectMCP, tool)
		}
	}
	require.NotEmpty(t, projectMCP)
	assert.Equal(t, "vscode-project-tool", projectMCP[0].Name)
	assert.Equal(t, vscodeApp, projectMCP[0].App)
}

func TestVSCodeDiscoverer_MissingConfig(t *testing.T) {
	reader, err := NewVSCodeDiscoverer(DiscoveryConfig{HomeDir: t.TempDir()})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err)
	assert.Empty(t, tools)
}

func TestVSCodeDiscoverer_DirExistsButNoMCPJson(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, mkdir(filepath.Join(tmpDir, ".vscode")))

	reader, err := NewVSCodeDiscoverer(DiscoveryConfig{HomeDir: tmpDir})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, inventory.KindCodingAgent, tools[0].Kind)
	assert.Equal(t, "VS Code", tools[0].Name)
}

// TestVSCodeDiscoverer_ServersKey verifies that project MCP files using
// the VS Code-native "servers" key are parsed correctly.
func TestVSCodeDiscoverer_ServersKey(t *testing.T) {
	fixtures := fixturesDir(t)
	tmpProject := t.TempDir()

	require.NoError(t, mkdir(filepath.Join(tmpProject, ".vscode")))
	require.NoError(t, copyFile(
		filepath.Join(fixtures, "vscode-project", "mcp.json"),
		filepath.Join(tmpProject, ".vscode", "mcp.json"),
	))

	reader, err := NewVSCodeDiscoverer(DiscoveryConfig{
		HomeDir:    t.TempDir(),
		ProjectDir: tmpProject,
	})
	require.NoError(t, err)

	var mcpServers []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		if tool.Kind == inventory.KindMCPServer {
			mcpServers = append(mcpServers, tool)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, mcpServers)
	assert.Equal(t, "vscode-project-tool", mcpServers[0].Name)
	assert.Equal(t, inventory.ScopeProject, mcpServers[0].Scope)
}

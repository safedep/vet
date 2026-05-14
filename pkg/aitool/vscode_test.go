package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVSCodeDiscoverer_WithFixtures(t *testing.T) {
	fixtures := fixturesDir(t)
	tmpDir := t.TempDir()

	err := copyDir(
		filepath.Join(fixtures, "vscode"),
		filepath.Join(tmpDir, ".vscode"),
	)
	require.NoError(t, err)

	reader, err := NewVSCodeDiscoverer(DiscoveryConfig{
		HomeDir:    tmpDir,
		ProjectDir: filepath.Join(fixtures, "vscode-project"),
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tools)

	var agents []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeCodingAgent {
			agents = append(agents, tool)
		}
	}
	require.Len(t, agents, 1)
	assert.Equal(t, "VS Code", agents[0].Name)
	assert.Equal(t, vscodeApp, agents[0].App)
	assert.Equal(t, AIToolScopeSystem, agents[0].Scope)

	var systemMCP []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer && tool.Scope == AIToolScopeSystem {
			systemMCP = append(systemMCP, tool)
		}
	}
	require.NotEmpty(t, systemMCP)
	assert.Equal(t, "vscode-global", systemMCP[0].Name)
	assert.Equal(t, vscodeApp, systemMCP[0].App)

	var projectMCP []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer && tool.Scope == AIToolScopeProject {
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

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
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

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, AIToolTypeCodingAgent, tools[0].Type)
	assert.Equal(t, "VS Code", tools[0].Name)
}

// TestVSCodeDiscoverer_ServersKey verifies that project MCP files using
// the VS Code-native "servers" key are parsed correctly.
func TestVSCodeDiscoverer_ServersKey(t *testing.T) {
	fixtures := fixturesDir(t)

	reader, err := NewVSCodeDiscoverer(DiscoveryConfig{
		HomeDir:    t.TempDir(),
		ProjectDir: filepath.Join(fixtures, "vscode-project"),
	})
	require.NoError(t, err)

	var mcpServers []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Type == AIToolTypeMCPServer {
			mcpServers = append(mcpServers, tool)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, mcpServers)
	assert.Equal(t, "vscode-project-tool", mcpServers[0].Name)
	assert.Equal(t, AIToolScopeProject, mcpServers[0].Scope)
}

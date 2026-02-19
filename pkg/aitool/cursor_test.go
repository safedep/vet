package aitool

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCursorDiscoverer_WithFixtures(t *testing.T) {
	fixtures := fixturesDir(t)

	// Set up tmpDir with .cursor structure
	tmpDir := t.TempDir()
	err := copyDir(filepath.Join(fixtures, "cursor"), filepath.Join(tmpDir, ".cursor"))
	require.NoError(t, err)

	reader, err := NewCursorDiscoverer(DiscoveryConfig{
		HomeDir:    tmpDir,
		ProjectDir: filepath.Join(fixtures, "cursor-project"),
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)

	// Should have: system MCP server(s) + coding_agent + project MCP server(s)
	assert.NotEmpty(t, tools)

	// Check for system MCP server "database"
	var systemMCPServers []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer && tool.Scope == AIToolScopeSystem {
			systemMCPServers = append(systemMCPServers, tool)
		}
	}
	require.NotEmpty(t, systemMCPServers)
	assert.Equal(t, "database", systemMCPServers[0].Name)
	assert.Equal(t, cursorHost, systemMCPServers[0].Host)

	// Check for coding agents
	var agents []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeCodingAgent {
			agents = append(agents, tool)
		}
	}
	require.NotEmpty(t, agents)
	assert.Equal(t, "Cursor", agents[0].Name)

	// Check that the project-scoped instruction files are emitted as project_config
	var projectConfigs []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeProjectConfig && tool.Scope == AIToolScopeProject {
			projectConfigs = append(projectConfigs, tool)
		}
	}
	require.NotEmpty(t, projectConfigs, "expected a project_config with instruction files")
	require.NotNil(t, projectConfigs[0].Agent)
	assert.NotEmpty(t, projectConfigs[0].Agent.InstructionFiles, "InstructionFiles should contain .cursorrules and rule files")

	// Verify both .cursorrules and .cursor/rules/rule1.md are present
	foundCursorRules := false
	foundRule1 := false
	for _, f := range projectConfigs[0].Agent.InstructionFiles {
		if filepath.Base(f) == ".cursorrules" {
			foundCursorRules = true
		}
		if filepath.Base(f) == "rule1.md" {
			foundRule1 = true
		}
	}
	assert.True(t, foundCursorRules, "should find .cursorrules in InstructionFiles")
	assert.True(t, foundRule1, "should find rule1.md in InstructionFiles")

	// Check for project MCP server
	var projectMCPServers []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer && tool.Scope == AIToolScopeProject {
			projectMCPServers = append(projectMCPServers, tool)
		}
	}
	require.NotEmpty(t, projectMCPServers)
	assert.Equal(t, "project-tool", projectMCPServers[0].Name)

	// Verify env var names only (no values)
	for _, s := range tools {
		if s.MCPServer != nil {
			for _, name := range s.MCPServer.EnvVarNames {
				assert.NotContains(t, name, "postgres://")
				assert.NotContains(t, name, "key-value")
			}
		}
	}
}

func TestCursorDiscoverer_MissingConfig(t *testing.T) {
	reader, err := NewCursorDiscoverer(DiscoveryConfig{
		HomeDir:    t.TempDir(),
		ProjectDir: t.TempDir(),
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err)
	assert.Empty(t, tools)
}

func TestCursorDiscoverer_DirExistsButNoMCPJson(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ~/.cursor/ directory without mcp.json
	err := mkdir(filepath.Join(tmpDir, ".cursor"))
	require.NoError(t, err)

	reader, err := NewCursorDiscoverer(DiscoveryConfig{
		HomeDir: tmpDir,
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)

	// Should still emit a coding_agent even without mcp.json
	require.Len(t, tools, 1)
	assert.Equal(t, AIToolTypeCodingAgent, tools[0].Type)
	assert.Equal(t, "Cursor", tools[0].Name)
	assert.Equal(t, AIToolScopeSystem, tools[0].Scope)
}

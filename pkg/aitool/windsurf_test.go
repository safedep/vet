package aitool

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindsurfDiscoverer_WithFixtures(t *testing.T) {
	fixtures := fixturesDir(t)

	// Build a tmpDir with .codeium/windsurf/ structure
	tmpDir := t.TempDir()
	err := copyDir(
		filepath.Join(fixtures, "windsurf"),
		filepath.Join(tmpDir, ".codeium", "windsurf"),
	)
	require.NoError(t, err)

	reader, err := NewWindsurfDiscoverer(DiscoveryConfig{
		HomeDir: tmpDir,
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tools)

	// Check coding_agent
	var agents []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeCodingAgent {
			agents = append(agents, tool)
		}
	}
	require.Len(t, agents, 1)
	assert.Equal(t, "Windsurf", agents[0].Name)
	assert.Equal(t, windsurfHost, agents[0].Host)
	assert.Equal(t, AIToolScopeSystem, agents[0].Scope)

	// Check MCP servers
	var mcpServers []*AITool
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer {
			mcpServers = append(mcpServers, tool)
		}
	}
	require.Len(t, mcpServers, 2)

	// Find the stdio and remote servers
	var stdioServer, remoteServer *AITool
	for _, s := range mcpServers {
		if s.Name == "local-server" {
			stdioServer = s
		}
		if s.Name == "remote-http-mcp" {
			remoteServer = s
		}
	}

	require.NotNil(t, stdioServer)
	assert.Equal(t, MCPTransportStdio, stdioServer.MCPServer.Transport)
	assert.Equal(t, "npx", stdioServer.MCPServer.Command)

	require.NotNil(t, remoteServer)
	assert.Equal(t, MCPTransportStreamableHTTP, remoteServer.MCPServer.Transport)
	assert.Equal(t, "https://example.com/mcp", remoteServer.MCPServer.URL)
	assert.Contains(t, remoteServer.MCPServer.HeaderNames, "Authorization")
}

func TestWindsurfDiscoverer_MissingConfig(t *testing.T) {
	reader, err := NewWindsurfDiscoverer(DiscoveryConfig{
		HomeDir: t.TempDir(),
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

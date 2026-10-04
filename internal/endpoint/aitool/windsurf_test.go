package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
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

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tools)

	// Check coding_agent
	var agents []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindCodingAgent {
			agents = append(agents, tool)
		}
	}
	require.Len(t, agents, 1)
	assert.Equal(t, "Windsurf", agents[0].Name)
	assert.Equal(t, windsurfApp, agents[0].App)
	assert.Equal(t, inventory.ScopeSystem, agents[0].Scope)

	// Check MCP servers
	var mcpServers []*inventory.Item
	for _, tool := range tools {
		if tool.Kind == inventory.KindMCPServer {
			mcpServers = append(mcpServers, tool)
		}
	}
	require.Len(t, mcpServers, 2)

	// Find the stdio and remote servers
	var stdioServer, remoteServer *inventory.Item
	for _, s := range mcpServers {
		if s.Name == "local-server" {
			stdioServer = s
		}
		if s.Name == "remote-http-mcp" {
			remoteServer = s
		}
	}

	require.NotNil(t, stdioServer)
	assert.Equal(t, inventory.TransportStdio, stdioServer.MCPServer.Transport)
	assert.Equal(t, "npx", stdioServer.MCPServer.Command)

	require.NotNil(t, remoteServer)
	assert.Equal(t, inventory.TransportStreamableHTTP, remoteServer.MCPServer.Transport)
	assert.Equal(t, "https://example.com/mcp", remoteServer.MCPServer.URL)
	assert.Contains(t, remoteServer.MCPServer.HeaderNames, "Authorization")
}

func TestWindsurfDiscoverer_MissingConfig(t *testing.T) {
	reader, err := NewWindsurfDiscoverer(DiscoveryConfig{
		HomeDir: t.TempDir(),
	})
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err)
	assert.Empty(t, tools)
}

package aitool

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMCPHostConfig(t *testing.T) {
	fixtures := fixturesDir(t)

	cfg, err := parseMCPHostConfig(filepath.Join(fixtures, "claude", "settings.json"))
	require.NoError(t, err)

	assert.Equal(t, "claude-sonnet-4-20250514", cfg.Model)
	assert.Contains(t, cfg.MCPServers, "global-server")

	server := cfg.MCPServers["global-server"]
	assert.Equal(t, "npx", server.Command)
	assert.Equal(t, []string{"-y", "@example/mcp-server"}, server.Args)
	assert.Contains(t, server.Env, "API_KEY")
}

func TestDetectTransport(t *testing.T) {
	t.Run("stdio_from_command", func(t *testing.T) {
		entry := mcpServerEntry{Command: "npx", Args: []string{"-y", "server"}}
		assert.Equal(t, MCPTransportStdio, detectTransport(entry))
	})

	t.Run("sse_from_url", func(t *testing.T) {
		entry := mcpServerEntry{URL: "http://localhost:3000/sse"}
		assert.Equal(t, MCPTransportSSE, detectTransport(entry))
	})

	t.Run("streamable_http_from_url", func(t *testing.T) {
		entry := mcpServerEntry{URL: "http://localhost:3000/api"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("explicit_sse_overrides_command", func(t *testing.T) {
		entry := mcpServerEntry{Type: "sse", Command: "npx", URL: "http://localhost/sse"}
		assert.Equal(t, MCPTransportSSE, detectTransport(entry))
	})

	t.Run("explicit_streamable_http_with_underscore", func(t *testing.T) {
		entry := mcpServerEntry{Type: "streamable_http", Command: "npx"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("explicit_streamable_http_with_hyphen", func(t *testing.T) {
		entry := mcpServerEntry{Type: "streamable-http", URL: "http://localhost/api"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("explicit_stdio", func(t *testing.T) {
		entry := mcpServerEntry{Type: "stdio", Command: "node"}
		assert.Equal(t, MCPTransportStdio, detectTransport(entry))
	})

	t.Run("serverUrl_streamable_http", func(t *testing.T) {
		entry := mcpServerEntry{ServerURL: "https://example.com/mcp"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("serverUrl_sse", func(t *testing.T) {
		entry := mcpServerEntry{ServerURL: "https://example.com/sse"}
		assert.Equal(t, MCPTransportSSE, detectTransport(entry))
	})
}

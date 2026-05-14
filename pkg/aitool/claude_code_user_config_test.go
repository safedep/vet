package aitool

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildUserConfigHomeDir creates a temp home directory containing:
//   - .claude.json         — user-level MCP registry (standard mcpServers format)
//   - .claude/plugins/cache/org/slack-plugin/1.0.0/.mcp.json  — standard format
//   - .claude/plugins/cache/org/context7-plugin/unknown/.mcp.json — bare format
func buildUserConfigHomeDir(t *testing.T) string {
	t.Helper()
	home := t.TempDir()

	writeJSONFile(t, filepath.Join(home, ".claude.json"), map[string]any{
		"numStartups": 42,
		"mcpServers": map[string]any{
			"context7": map[string]any{
				"type": "http",
				"url":  "https://mcp.context7.com/mcp",
			},
			"notion": map[string]any{
				"type": "http",
				"url":  "https://mcp.notion.com/mcp",
			},
		},
	})

	writeJSONFile(t, filepath.Join(home, ".claude", "plugins", "cache", "org", "slack-plugin", "1.0.0", ".mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"slack": map[string]any{
				"type": "http",
				"url":  "https://mcp.slack.com/mcp",
			},
		},
	})

	writeJSONFile(t, filepath.Join(home, ".claude", "plugins", "cache", "org", "context7-plugin", "unknown", ".mcp.json"), map[string]any{
		"plugin-context7": map[string]any{
			"command": "npx",
			"args":    []string{"-y", "@upstash/context7-mcp"},
		},
	})

	return home
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	data, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
}

func TestClaudeCodeUserConfigDiscoverer_ReadsUserLevelMCPs(t *testing.T) {
	home := buildUserConfigHomeDir(t)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(t *AITool) error {
		tools = append(tools, t)
		return nil
	}))

	mcpNames := collectMCPNames(tools)
	assert.Contains(t, mcpNames, "context7", "should discover context7 from ~/.claude.json")
	assert.Contains(t, mcpNames, "notion", "should discover notion from ~/.claude.json")
}

func TestClaudeCodeUserConfigDiscoverer_ReadsPluginCache_StandardFormat(t *testing.T) {
	home := buildUserConfigHomeDir(t)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(t *AITool) error {
		tools = append(tools, t)
		return nil
	}))

	mcpNames := collectMCPNames(tools)
	assert.Contains(t, mcpNames, "slack", "should discover slack from plugin cache standard-format .mcp.json")
}

func TestClaudeCodeUserConfigDiscoverer_ReadsPluginCache_BareFormat(t *testing.T) {
	home := buildUserConfigHomeDir(t)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(t *AITool) error {
		tools = append(tools, t)
		return nil
	}))

	mcpNames := collectMCPNames(tools)
	assert.Contains(t, mcpNames, "plugin-context7", "should discover plugin-context7 from bare-format .mcp.json")
}

func TestClaudeCodeUserConfigDiscoverer_AllToolsAreSystemScoped(t *testing.T) {
	home := buildUserConfigHomeDir(t)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		assert.Equal(t, AIToolScopeSystem, tool.Scope, "all user-config tools must be system-scoped")
		return nil
	}))
}

func TestClaudeCodeUserConfigDiscoverer_AllToolsAreClaudeCodeApp(t *testing.T) {
	home := buildUserConfigHomeDir(t)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		assert.Equal(t, claudeCodeApp, tool.App)
		return nil
	}))
}

func TestClaudeCodeUserConfigDiscoverer_MissingHomeDir_HandledGracefully(t *testing.T) {
	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir: t.TempDir(), // empty home — no .claude.json, no plugin cache
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err)
	assert.Empty(t, tools)
}

func TestClaudeCodeUserConfigDiscoverer_ProjectScopeOnly_EmitsNothing(t *testing.T) {
	home := buildUserConfigHomeDir(t)

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir: home,
		Scope:   scope,
	})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))
	assert.Empty(t, tools, "project-only scope should produce no items from user config")
}

func TestClaudeCodeUserConfigDiscoverer_Name(t *testing.T) {
	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: t.TempDir()})
	require.NoError(t, err)
	assert.NotEmpty(t, reader.Name())
}

// collectMCPNames extracts the names of all MCP server tools.
func collectMCPNames(tools []*AITool) []string {
	var names []string
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer {
			names = append(names, tool.Name)
		}
	}
	return names
}

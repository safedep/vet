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

func TestClaudeCodeUserConfigDiscoverer_UserLevelMCPs_AreSystemScoped(t *testing.T) {
	// buildUserConfigHomeDir has top-level mcpServers + plugin cache but NO projects key.
	// Every item emitted must therefore be system-scoped.
	home := buildUserConfigHomeDir(t)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		assert.Equal(t, AIToolScopeSystem, tool.Scope, "user-scope and plugin-cache MCPs must be system-scoped")
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

// --- project-specific MCPs from ~/.claude.json["projects"] ---

// buildHomeWithProjectMCPs creates a temp home with a ~/.claude.json that has
// per-project mcpServers under the "projects" key.
func buildHomeWithProjectMCPs(t *testing.T, projectEntries map[string]any) string {
	t.Helper()
	home := t.TempDir()
	writeJSONFile(t, filepath.Join(home, ".claude.json"), map[string]any{
		"projects": projectEntries,
	})
	return home
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_EmittedAsProjectScoped(t *testing.T) {
	// items under projects[*] in ~/.claude.json are Claude Code "local" scope —
	// they must be emitted as AIToolScopeProject, not AIToolScopeSystem.
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{
				"project-notion": map[string]any{"type": "http", "url": "https://mcp.notion.com/mcp"},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))

	assert.Contains(t, collectMCPNames(tools), "project-notion",
		"project-specific MCP should be discovered")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_ScopeIsProject(t *testing.T) {
	// Claude Code's "local" scope (projects[path].mcpServers) must produce
	// AIToolScopeProject items, not AIToolScopeSystem.
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{
				"proj-server": map[string]any{"command": "npx", "args": []string{"-y", "some-mcp"}},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Type == AIToolTypeMCPServer && tool.Name == "proj-server" {
			assert.Equal(t, AIToolScopeProject, tool.Scope,
				"projects[path].mcpServers are local-scope; must be AIToolScopeProject")
		}
		return nil
	}))
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_ConfigPathIsProjectPath(t *testing.T) {
	const projPath = "/home/user/myproject"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		projPath: map[string]any{
			"mcpServers": map[string]any{
				"proj-server": map[string]any{"command": "npx"},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Type == AIToolTypeMCPServer && tool.Name == "proj-server" {
			assert.Equal(t, projPath, tool.ConfigPath,
				"ConfigPath must be the project path so IDs are unique per project")
		}
		return nil
	}))
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_EmptyMCPServersSkipped(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/proj-a": map[string]any{"mcpServers": map[string]any{}},
		"/home/user/proj-b": map[string]any{
			"mcpServers": map[string]any{
				"real-server": map[string]any{"command": "npx"},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))

	names := collectMCPNames(tools)
	assert.Contains(t, names, "real-server")
	assert.NotContains(t, names, "",
		"project with empty mcpServers should not emit a nameless tool")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_DisabledServerHasEnabledFalse(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{
				"active-server":   map[string]any{"command": "npx"},
				"disabled-server": map[string]any{"command": "node"},
			},
			"disabledMcpServers": []string{"disabled-server"},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	toolByName := map[string]*AITool{}
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Type == AIToolTypeMCPServer {
			toolByName[tool.Name] = tool
		}
		return nil
	}))

	require.Contains(t, toolByName, "disabled-server")
	require.NotNil(t, toolByName["disabled-server"].Enabled)
	assert.False(t, *toolByName["disabled-server"].Enabled,
		"server in disabledMcpServers must have Enabled=false")

	require.Contains(t, toolByName, "active-server")
	// active-server has no disabled field set → Enabled is nil (unspecified)
	assert.Nil(t, toolByName["active-server"].Enabled,
		"server not in disabledMcpServers must not have Enabled forced to false")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_DisabledNameNotInMCPServers_Safe(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{
				"real-server": map[string]any{"command": "npx"},
			},
			"disabledMcpServers": []string{"ghost-server"}, // not in mcpServers
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err, "disabledMcpServers referencing unknown server must not error")
	assert.Contains(t, collectMCPNames(tools), "real-server")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_MultipleProjects_AllEmitted(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/proj-a": map[string]any{
			"mcpServers": map[string]any{
				"server-a": map[string]any{"command": "npx"},
			},
		},
		"/home/user/proj-b": map[string]any{
			"mcpServers": map[string]any{
				"server-b": map[string]any{"command": "node"},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))

	names := collectMCPNames(tools)
	assert.Contains(t, names, "server-a", "project A server must be emitted")
	assert.Contains(t, names, "server-b", "project B server must be emitted")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_SameNameDiffProject_DiffIDs(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/proj-a": map[string]any{
			"mcpServers": map[string]any{
				"notion": map[string]any{"type": "http", "url": "https://mcp.notion.com/mcp"},
			},
		},
		"/home/user/proj-b": map[string]any{
			"mcpServers": map[string]any{
				"notion": map[string]any{"type": "http", "url": "https://mcp.notion.com/mcp"},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Type == AIToolTypeMCPServer {
			tools = append(tools, tool)
		}
		return nil
	}))

	notionTools := []*AITool{}
	for _, t := range tools {
		if t.Name == "notion" {
			notionTools = append(notionTools, t)
		}
	}
	require.Len(t, notionTools, 2, "both projects' notion entries must be emitted")
	assert.NotEqual(t, notionTools[0].ID, notionTools[1].ID,
		"same server name from different projects must have different IDs")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_MissingProjectsKey_Graceful(t *testing.T) {
	home := t.TempDir()
	writeJSONFile(t, filepath.Join(home, ".claude.json"), map[string]any{
		"mcpServers": map[string]any{
			"global": map[string]any{"command": "npx"},
		},
		// no "projects" key
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err, "missing projects key must not error")
	assert.Contains(t, collectMCPNames(tools), "global",
		"global mcpServers must still be discovered")
}

// --- current-project verification (via processAllProjectMCPs) ---

func TestClaudeCodeUserConfigDiscoverer_LocalScopeMCPs_AppearAsProjectScoped(t *testing.T) {
	// Verifies end-to-end that a specific project's local-scope MCPs arrive
	// with AIToolScopeProject (not system-scoped).
	const projDir = "/home/user/myproject"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		projDir: map[string]any{
			"mcpServers": map[string]any{
				"local-server": map[string]any{"command": "npx"},
			},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var found *AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Name == "local-server" {
			found = tool
		}
		return nil
	}))

	require.NotNil(t, found, "local-scope MCP must be discovered")
	assert.Equal(t, AIToolScopeProject, found.Scope)
	assert.Equal(t, projDir, found.ConfigPath)
}

func TestClaudeCodeUserConfigDiscoverer_LocalScopeMCPs_EmptyMCPServers_NoItems(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))
	assert.Empty(t, collectMCPNames(tools))
}

func TestClaudeCodeUserConfigDiscoverer_LocalScopeMCPs_DisabledServer(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{
				"github": map[string]any{"type": "http", "url": "https://api.githubcopilot.com/mcp"},
			},
			"disabledMcpServers": []string{"github"},
		},
	})

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{HomeDir: home})
	require.NoError(t, err)

	var found *AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Name == "github" {
			found = tool
		}
		return nil
	}))

	require.NotNil(t, found)
	require.NotNil(t, found.Enabled)
	assert.False(t, *found.Enabled, "disabled local-scope server must have Enabled=false")
}

// --- scope filtering ---

func TestClaudeCodeUserConfigDiscoverer_ProjectScopeOnly_EmitsAllProjectMCPs(t *testing.T) {
	// With project-only scope:
	// - projects[*].mcpServers (local-scope) must all appear as AIToolScopeProject
	// - top-level mcpServers (user-scope) and plugin cache must NOT appear
	home := t.TempDir()
	writeJSONFile(t, filepath.Join(home, ".claude.json"), map[string]any{
		"mcpServers": map[string]any{
			"user-global": map[string]any{"command": "npx"},
		},
		"projects": map[string]any{
			"/home/user/proj-a": map[string]any{
				"mcpServers": map[string]any{
					"proj-a-server": map[string]any{"command": "npx"},
				},
			},
			"/home/user/proj-b": map[string]any{
				"mcpServers": map[string]any{
					"proj-b-server": map[string]any{"command": "node"},
				},
			},
		},
	})

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

	names := collectMCPNames(tools)
	assert.Contains(t, names, "proj-a-server", "local-scope MCPs must appear under project scope")
	assert.Contains(t, names, "proj-b-server", "all projects' local MCPs must appear")
	assert.NotContains(t, names, "user-global",
		"user-scope MCPs must NOT appear when scope is project-only")

	for _, tool := range tools {
		assert.Equal(t, AIToolScopeProject, tool.Scope,
			"all items under project scope must be AIToolScopeProject")
	}
}

func TestClaudeCodeUserConfigDiscoverer_SystemScopeOnly_NoProjectMCPs(t *testing.T) {
	// With system-only scope, projects[*].mcpServers must NOT be emitted.
	// Only user-scope (top-level mcpServers) and plugin cache items appear.
	home := t.TempDir()
	writeJSONFile(t, filepath.Join(home, ".claude.json"), map[string]any{
		"mcpServers": map[string]any{
			"user-global": map[string]any{"command": "npx"},
		},
		"projects": map[string]any{
			"/home/user/proj": map[string]any{
				"mcpServers": map[string]any{
					"local-only": map[string]any{"command": "node"},
				},
			},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeSystem)
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

	names := collectMCPNames(tools)
	assert.Contains(t, names, "user-global", "user-scope MCPs must appear under system scope")
	assert.NotContains(t, names, "local-only",
		"local-scope project MCPs must NOT appear when scope is system-only")

	for _, tool := range tools {
		assert.Equal(t, AIToolScopeSystem, tool.Scope,
			"system-only scope must produce only system-scoped items")
	}
}

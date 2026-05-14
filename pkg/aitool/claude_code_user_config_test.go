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

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_EmittedAsSystemScoped(t *testing.T) {
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
		"project-specific MCP should be discovered in system scope")
}

func TestClaudeCodeUserConfigDiscoverer_ProjectMCPs_SystemScopedTag(t *testing.T) {
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
			assert.Equal(t, AIToolScopeSystem, tool.Scope,
				"project-local MCPs emitted during system scan must be system-scoped")
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

// --- current-project scope (AIToolScopeProject) ---

func TestClaudeCodeUserConfigDiscoverer_CurrentProject_EmittedAsProjectScoped(t *testing.T) {
	const projDir = "/home/user/myproject"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		projDir: map[string]any{
			"mcpServers": map[string]any{
				"local-server": map[string]any{"command": "npx"},
			},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: projDir,
		Scope:      scope,
	})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))

	require.Contains(t, collectMCPNames(tools), "local-server")

	for _, tool := range tools {
		if tool.Name == "local-server" {
			assert.Equal(t, AIToolScopeProject, tool.Scope)
		}
	}
}

func TestClaudeCodeUserConfigDiscoverer_CurrentProject_NotInMap_NoItemsNoError(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/other-project": map[string]any{
			"mcpServers": map[string]any{
				"other-server": map[string]any{"command": "npx"},
			},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: "/home/user/completely-different-project",
		Scope:      scope,
	})
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	assert.NoError(t, err)
	assert.Empty(t, collectMCPNames(tools),
		"project not in map should yield no MCP items")
}

func TestClaudeCodeUserConfigDiscoverer_CurrentProject_EmptyMCPServers_NoItems(t *testing.T) {
	const projDir = "/home/user/myproject"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		projDir: map[string]any{
			"mcpServers": map[string]any{},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: projDir,
		Scope:      scope,
	})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))
	assert.Empty(t, collectMCPNames(tools))
}

func TestClaudeCodeUserConfigDiscoverer_CurrentProject_DisabledServer(t *testing.T) {
	const projDir = "/home/user/myproject"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		projDir: map[string]any{
			"mcpServers": map[string]any{
				"github": map[string]any{"type": "http", "url": "https://api.githubcopilot.com/mcp"},
			},
			"disabledMcpServers": []string{"github"},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: projDir,
		Scope:      scope,
	})
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
	assert.False(t, *found.Enabled, "project-scope disabled server must have Enabled=false")
}

func TestClaudeCodeUserConfigDiscoverer_CurrentProject_NoProjectDir_NoItems(t *testing.T) {
	home := buildHomeWithProjectMCPs(t, map[string]any{
		"/home/user/myproject": map[string]any{
			"mcpServers": map[string]any{
				"server": map[string]any{"command": "npx"},
			},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: "", // no project dir
		Scope:      scope,
	})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))
	assert.Empty(t, collectMCPNames(tools),
		"project scope with no projectDir must not emit any items")
}

// --- scope filtering ---

func TestClaudeCodeUserConfigDiscoverer_ProjectScopeOnly_SkipsSystemProjectWalk(t *testing.T) {
	// When scope is project-only, the full project walk (all projects) must NOT run.
	// Only the current project's MCPs may appear.
	const currProj = "/home/user/current"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		currProj: map[string]any{
			"mcpServers": map[string]any{
				"current-server": map[string]any{"command": "npx"},
			},
		},
		"/home/user/other": map[string]any{
			"mcpServers": map[string]any{
				"other-server": map[string]any{"command": "node"},
			},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: currProj,
		Scope:      scope,
	})
	require.NoError(t, err)

	var tools []*AITool
	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	}))

	names := collectMCPNames(tools)
	assert.Contains(t, names, "current-server", "current project MCPs must be emitted in project scope")
	assert.NotContains(t, names, "other-server",
		"other projects must NOT be emitted when scope is project-only")
}

func TestClaudeCodeUserConfigDiscoverer_SystemScopeOnly_SkipsCurrentProjectLookup(t *testing.T) {
	// When scope is system-only, the current project MCPs are emitted as system-scoped
	// (via the all-projects walk) and NOT again as project-scoped.
	const currProj = "/home/user/current"
	home := buildHomeWithProjectMCPs(t, map[string]any{
		currProj: map[string]any{
			"mcpServers": map[string]any{
				"srv": map[string]any{"command": "npx"},
			},
		},
	})

	scope, err := NewDiscoveryScope(AIToolScopeSystem)
	require.NoError(t, err)

	reader, err := NewClaudeCodeUserConfigDiscoverer(DiscoveryConfig{
		HomeDir:    home,
		ProjectDir: currProj,
		Scope:      scope,
	})
	require.NoError(t, err)

	require.NoError(t, reader.EnumTools(context.Background(), func(tool *AITool) error {
		if tool.Type == AIToolTypeMCPServer && tool.Name == "srv" {
			assert.Equal(t, AIToolScopeSystem, tool.Scope,
				"system-only scope must not emit project-scoped items")
		}
		return nil
	}))
}

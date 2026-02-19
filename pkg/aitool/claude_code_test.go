package aitool

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixturesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(file), "fixtures")
}

func TestClaudeCodeDiscoverer_SystemSettings(t *testing.T) {
	fixtures := fixturesDir(t)

	config := DiscoveryConfig{
		HomeDir: fixtures, // fixtures/claude/ maps to ~/.claude/
	}

	// We need to restructure: HomeDir should be the parent of .claude/
	// fixtures dir has a "claude" subdir that represents .claude
	// But the discoverer looks for HomeDir/.claude/settings.json
	// So HomeDir should be fixtures root, and fixtures should have .claude/settings.json
	// Let's use a temp approach: HomeDir = fixtures, .claude dir = fixtures/.claude not fixtures/claude

	// Actually the fixture is at fixtures/claude/settings.json
	// But the code looks for HomeDir/.claude/settings.json
	// We need HomeDir such that HomeDir/.claude = fixtures/claude
	// That means HomeDir = fixtures (since fixtures/claude exists... but we need .claude)
	// Let's adjust: use the fixture dir structure where .claude is a symlink or rename

	// The simplest approach: the fixture dir at fixtures/ serves as $HOME
	// So we need fixtures/.claude/settings.json, not fixtures/claude/settings.json
	// But we used fixtures/claude/ path. Let me just point homeDir correctly.

	// fixtures/ IS the home dir, and fixtures/.claude would be needed
	// But we created fixtures/claude/ not fixtures/.claude/
	// For tests, we can just point directly. Let's test with the actual file path.

	// Actually, let me use the parent of "claude" as homeDir, since the discoverer
	// expects $HOME/.claude/settings.json, and we have fixtures/claude/settings.json
	// This won't work because .claude != claude

	// Let's just use a discoverer that has the correct HomeDir
	// We'll use a path where we can create a .claude symlink or just test differently

	// Simplest: test parseClaudeCodeConfig directly, and test the discoverer
	// with a tempdir

	t.Run("parseClaudeCodeConfig", func(t *testing.T) {
		cfg, err := parseClaudeCodeConfig(filepath.Join(fixtures, "claude", "settings.json"))
		require.NoError(t, err)

		assert.Equal(t, "claude-sonnet-4-20250514", cfg.Model)
		assert.Contains(t, cfg.MCPServers, "global-server")

		server := cfg.MCPServers["global-server"]
		assert.Equal(t, "npx", server.Command)
		assert.Equal(t, []string{"-y", "@example/mcp-server"}, server.Args)
		assert.Contains(t, server.Env, "API_KEY")
	})

	t.Run("detectTransport_stdio", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{Command: "npx", Args: []string{"-y", "server"}}
		assert.Equal(t, MCPTransportStdio, detectTransport(entry))
	})

	t.Run("detectTransport_sse_url", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{URL: "http://localhost:3000/sse"}
		assert.Equal(t, MCPTransportSSE, detectTransport(entry))
	})

	t.Run("detectTransport_http_url", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{URL: "http://localhost:3000/api"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("detectTransport_explicit_sse_overrides_command", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{Type: "sse", Command: "npx", URL: "http://localhost/sse"}
		assert.Equal(t, MCPTransportSSE, detectTransport(entry))
	})

	t.Run("detectTransport_explicit_streamable_http_with_underscore", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{Type: "streamable_http", Command: "npx"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("detectTransport_explicit_streamable_http_with_hyphen", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{Type: "streamable-http", URL: "http://localhost/api"}
		assert.Equal(t, MCPTransportStreamableHTTP, detectTransport(entry))
	})

	t.Run("detectTransport_explicit_stdio", func(t *testing.T) {
		entry := claudeCodeMCPServerEntry{Type: "stdio", Command: "node"}
		assert.Equal(t, MCPTransportStdio, detectTransport(entry))
	})

	t.Run("DiscovererWithFixtures", func(t *testing.T) {
		// Use a tmpdir approach with symlink for .claude
		tmpDir := t.TempDir()

		// Copy fixture data into tmpDir/.claude structure by creating symlink
		err := copyDir(filepath.Join(fixtures, "claude"), filepath.Join(tmpDir, ".claude"))
		require.NoError(t, err)

		reader, err := NewClaudeCodeDiscoverer(DiscoveryConfig{
			HomeDir:    tmpDir,
			ProjectDir: filepath.Join(fixtures, "project"),
		})
		require.NoError(t, err)

		var tools []*AITool
		err = reader.EnumTools(func(tool *AITool) error {
			tools = append(tools, tool)
			return nil
		})
		require.NoError(t, err)

		// Should have: 1 coding_agent + 1 system MCP server + 1 project MCP server from
		// projects/test-project + MCP servers from project/.mcp.json + project/.claude/settings.json
		assert.NotEmpty(t, tools)

		// Check coding agent
		var agents []*AITool
		for _, tool := range tools {
			if tool.Type == AIToolTypeCodingAgent {
				agents = append(agents, tool)
			}
		}
		require.NotEmpty(t, agents)
		assert.Equal(t, "Claude Code", agents[0].Name)
		assert.Equal(t, claudeCodeHost, agents[0].Host)
		assert.Equal(t, AIToolScopeSystem, agents[0].Scope)
		require.NotNil(t, agents[0].Agent)
		assert.Equal(t, "allowedTools", agents[0].Agent.PermissionMode)
		assert.Equal(t, "claude-sonnet-4-20250514", agents[0].Agent.Model)

		// Check MCP servers
		var mcpServers []*AITool
		for _, tool := range tools {
			if tool.Type == AIToolTypeMCPServer {
				mcpServers = append(mcpServers, tool)
			}
		}
		assert.NotEmpty(t, mcpServers)

		// Verify no secret values in env var names
		for _, s := range mcpServers {
			if s.MCPServer != nil {
				for _, envName := range s.MCPServer.EnvVarNames {
					assert.NotContains(t, envName, "secret")
					assert.NotContains(t, envName, "sk-ant")
				}
			}
		}

		// Verify args are sanitized
		for _, s := range mcpServers {
			if s.MCPServer != nil {
				for _, arg := range s.MCPServer.Args {
					assert.NotContains(t, arg, "secret123")
				}
			}
		}

		// Check that CLAUDE.md is emitted as project_config, not coding_agent
		var projectConfigs []*AITool
		for _, tool := range tools {
			if tool.Type == AIToolTypeProjectConfig && tool.Scope == AIToolScopeProject {
				projectConfigs = append(projectConfigs, tool)
			}
		}
		require.NotEmpty(t, projectConfigs, "expected a project_config with CLAUDE.md")
		require.NotNil(t, projectConfigs[0].Agent)
		assert.NotEmpty(t, projectConfigs[0].Agent.InstructionFiles)

		foundClaudeMD := false
		for _, f := range projectConfigs[0].Agent.InstructionFiles {
			if filepath.Base(f) == "CLAUDE.md" {
				foundClaudeMD = true
			}
		}
		assert.True(t, foundClaudeMD, "should find CLAUDE.md in InstructionFiles")

		// Verify no project-scoped coding_agent exists
		for _, tool := range tools {
			if tool.Type == AIToolTypeCodingAgent {
				assert.NotEqual(t, AIToolScopeProject, tool.Scope,
					"coding_agent should only be system-scoped")
			}
		}
	})

	t.Run("MissingConfigHandledGracefully", func(t *testing.T) {
		reader, err := NewClaudeCodeDiscoverer(config)
		require.NoError(t, err)

		// Should not error with non-existent paths
		var tools []*AITool
		err = reader.EnumTools(func(tool *AITool) error {
			tools = append(tools, tool)
			return nil
		})
		assert.NoError(t, err)
	})
}

// copyDir copies a directory tree using os functions.
func copyDir(src, dst string) error {
	return copyDirRecursive(src, dst)
}

func copyDirRecursive(src, dst string) error {
	entries, err := filepath.Glob(filepath.Join(src, "*"))
	if err != nil {
		return err
	}

	if err := mkdir(dst); err != nil {
		return err
	}

	for _, entry := range entries {
		info, err := statFile(entry)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, filepath.Base(entry))
		if info.IsDir() {
			if err := copyDirRecursive(entry, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(entry, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

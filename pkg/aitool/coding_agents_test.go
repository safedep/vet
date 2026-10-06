package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateAgentEnv clears env vars that relocate agent config so tests only
// see the fixture home.
func isolateAgentEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"CODEX_HOME", "COPILOT_HOME", "APPDATA", "LOCALAPPDATA", "ProgramFiles"} {
		t.Setenv(key, "")
	}
}

// agentsFixtureHome copies fixtures/agents/home into a temp dir used as HOME.
func agentsFixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	require.NoError(t, copyDir(filepath.Join(fixturesDir(t), "agents", "home"), home))
	return home
}

func collectTools(t *testing.T, factory AIToolDiscovererFactory, config DiscoveryConfig) []*AITool {
	t.Helper()
	reader, err := factory(config)
	require.NoError(t, err)

	var tools []*AITool
	err = reader.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})
	require.NoError(t, err)
	return tools
}

type codingAgentCase struct {
	name                 string
	factory              AIToolDiscovererFactory
	app                  string
	appDisplay           string
	wantAgent            bool
	wantSystemMCP        map[string]MCPTransport
	wantProjectMCP       map[string]MCPTransport
	wantInstructionFiles []string
}

var codingAgentCases = []codingAgentCase{
	{
		name: "Codex", factory: NewCodexDiscoverer, app: codexApp, appDisplay: codexAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"codex-stdio":  MCPTransportStdio,
			"codex-remote": MCPTransportStreamableHTTP,
		},
		wantProjectMCP: map[string]MCPTransport{"codex-project": MCPTransportStdio},
	},
	{
		name: "GeminiCLI", factory: NewGeminiDiscoverer, app: geminiApp, appDisplay: geminiAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"gemini-stdio": MCPTransportStdio,
			"gemini-http":  MCPTransportStreamableHTTP,
			"gemini-sse":   MCPTransportSSE,
		},
		wantProjectMCP:       map[string]MCPTransport{"gemini-project": MCPTransportStdio},
		wantInstructionFiles: []string{"GEMINI.md"},
	},
	{
		name: "CopilotCLI", factory: NewCopilotDiscoverer, app: copilotApp, appDisplay: copilotAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"copilot-local": MCPTransportStdio,
			"copilot-http":  MCPTransportStreamableHTTP,
		},
		wantProjectMCP: map[string]MCPTransport{"copilot-project": MCPTransportStdio},
	},
	{
		name: "OpenCode", factory: NewOpenCodeDiscoverer, app: openCodeApp, appDisplay: openCodeAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"opencode-local":  MCPTransportStdio,
			"opencode-remote": MCPTransportStreamableHTTP,
		},
		wantProjectMCP: map[string]MCPTransport{"opencode-project": MCPTransportStreamableHTTP},
	},
	{
		name: "QwenCode", factory: NewQwenCodeDiscoverer, app: qwenCodeApp, appDisplay: qwenCodeAppDisplay,
		wantAgent:            true,
		wantSystemMCP:        map[string]MCPTransport{"qwen-stdio": MCPTransportStdio},
		wantProjectMCP:       map[string]MCPTransport{"qwen-project": MCPTransportStreamableHTTP},
		wantInstructionFiles: []string{"QWEN.md"},
	},
	{
		name: "Amp", factory: NewAmpDiscoverer, app: ampApp, appDisplay: ampAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"amp-stdio":  MCPTransportStdio,
			"amp-remote": MCPTransportStreamableHTTP,
		},
		wantProjectMCP: map[string]MCPTransport{"amp-project": MCPTransportStdio},
	},
	{
		name: "Augment", factory: NewAugmentDiscoverer, app: augmentApp, appDisplay: augmentAppDisplay,
		wantAgent:     true,
		wantSystemMCP: map[string]MCPTransport{"augment-stdio": MCPTransportStdio},
	},
	{
		name: "Kiro", factory: NewKiroDiscoverer, app: kiroApp, appDisplay: kiroAppDisplay,
		wantAgent:            true,
		wantSystemMCP:        map[string]MCPTransport{"kiro-stdio": MCPTransportStdio},
		wantProjectMCP:       map[string]MCPTransport{"kiro-project": MCPTransportStreamableHTTP},
		wantInstructionFiles: []string{"steering"},
	},
	{
		name: "AmazonQ", factory: NewAmazonQConfigDiscoverer, app: amazonQApp, appDisplay: amazonQAppDisplay,
		wantAgent:      true,
		wantSystemMCP:  map[string]MCPTransport{"amazonq-stdio": MCPTransportStdio},
		wantProjectMCP: map[string]MCPTransport{"amazonq-project": MCPTransportStdio},
	},
	{
		name: "Junie", factory: NewJunieDiscoverer, app: junieApp, appDisplay: junieAppDisplay,
		wantAgent:            true,
		wantSystemMCP:        map[string]MCPTransport{"junie-stdio": MCPTransportStdio},
		wantProjectMCP:       map[string]MCPTransport{"junie-project": MCPTransportStdio},
		wantInstructionFiles: []string{"guidelines.md"},
	},
	{
		name: "Goose", factory: NewGooseDiscoverer, app: gooseApp, appDisplay: gooseAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"goose-stdio": MCPTransportStdio,
			"goose-http":  MCPTransportStreamableHTTP,
		},
		wantInstructionFiles: []string{".goosehints"},
	},
	{
		name: "Continue", factory: NewContinueDiscoverer, app: continueApp, appDisplay: continueAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"continue-sqlite": MCPTransportStdio,
			"continue-remote": MCPTransportStreamableHTTP,
		},
		wantProjectMCP: map[string]MCPTransport{"continue-project": MCPTransportStdio},
	},
	{
		name: "Zed", factory: NewZedDiscoverer, app: zedApp, appDisplay: zedAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"zed-stdio":  MCPTransportStdio,
			"zed-legacy": MCPTransportStdio,
			"zed-remote": MCPTransportStreamableHTTP,
		},
	},
	{
		name: "Cline", factory: NewClineDiscoverer, app: clineApp, appDisplay: clineAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]MCPTransport{
			"cline-ext-stdio":  MCPTransportStdio,
			"cline-cli-remote": MCPTransportSSE,
		},
		wantInstructionFiles: []string{".clinerules"},
	},
	{
		name: "RooCode", factory: NewRooCodeDiscoverer, app: rooCodeApp, appDisplay: rooCodeAppDisplay,
		wantSystemMCP:  map[string]MCPTransport{"roo-stdio": MCPTransportStdio},
		wantProjectMCP: map[string]MCPTransport{"roo-project": MCPTransportStdio},
	},
}

func TestCodingAgentDiscoverers_WithFixtures(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)
	projectDir := filepath.Join(fixturesDir(t), "agents", "project")

	for _, tc := range codingAgentCases {
		t.Run(tc.name, func(t *testing.T) {
			tools := collectTools(t, tc.factory, DiscoveryConfig{HomeDir: home, ProjectDir: projectDir})

			gotSystemMCP := map[string]MCPTransport{}
			gotProjectMCP := map[string]MCPTransport{}
			var agents, projectConfigs []*AITool
			for _, tool := range tools {
				assert.Equal(t, tc.app, tool.App, "tool %s reported under wrong app", tool.Name)
				assert.Equal(t, tc.appDisplay, tool.AppDisplay)
				assert.NotEmpty(t, tool.ID)
				assert.NotEmpty(t, tool.SourceID)

				switch tool.Type {
				case AIToolTypeMCPServer:
					require.NotNil(t, tool.MCPServer)
					if tool.Scope == AIToolScopeSystem {
						gotSystemMCP[tool.Name] = tool.MCPServer.Transport
					} else {
						gotProjectMCP[tool.Name] = tool.MCPServer.Transport
					}
				case AIToolTypeCodingAgent:
					agents = append(agents, tool)
				case AIToolTypeProjectConfig:
					projectConfigs = append(projectConfigs, tool)
				default:
					t.Errorf("unexpected tool type %s", tool.Type)
				}
			}

			if tc.wantAgent {
				require.Len(t, agents, 1)
				assert.Equal(t, tc.appDisplay, agents[0].Name)
				assert.Equal(t, AIToolScopeSystem, agents[0].Scope)
			} else {
				assert.Empty(t, agents)
			}

			assert.Equal(t, tc.wantSystemMCP, gotSystemMCP)
			if tc.wantProjectMCP == nil {
				assert.Empty(t, gotProjectMCP)
			} else {
				assert.Equal(t, tc.wantProjectMCP, gotProjectMCP)
			}

			if len(tc.wantInstructionFiles) == 0 {
				assert.Empty(t, projectConfigs)
				return
			}
			require.Len(t, projectConfigs, 1)
			assert.Equal(t, AIToolScopeProject, projectConfigs[0].Scope)
			var names []string
			for _, f := range projectConfigs[0].Agent.InstructionFiles {
				names = append(names, filepath.Base(f))
			}
			assert.ElementsMatch(t, tc.wantInstructionFiles, names)
		})
	}
}

func TestCodingAgentDiscoverers_EmptyHome(t *testing.T) {
	isolateAgentEnv(t)
	emptyProject := t.TempDir()

	for _, tc := range codingAgentCases {
		t.Run(tc.name, func(t *testing.T) {
			tools := collectTools(t, tc.factory, DiscoveryConfig{HomeDir: t.TempDir(), ProjectDir: emptyProject})
			assert.Empty(t, tools)
		})
	}
}

func TestCodingAgentDiscoverers_ScopeFiltering(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)
	projectDir := filepath.Join(fixturesDir(t), "agents", "project")

	systemOnly, err := NewDiscoveryScope(AIToolScopeSystem)
	require.NoError(t, err)
	projectOnly, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	for _, tc := range codingAgentCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range collectTools(t, tc.factory, DiscoveryConfig{HomeDir: home, ProjectDir: projectDir, Scope: systemOnly}) {
				assert.Equal(t, AIToolScopeSystem, tool.Scope)
			}
			for _, tool := range collectTools(t, tc.factory, DiscoveryConfig{HomeDir: home, ProjectDir: projectDir, Scope: projectOnly}) {
				assert.Equal(t, AIToolScopeProject, tool.Scope)
			}
		})
	}
}

func TestGeminiDiscoverer_AntigravityDirIsNotGeminiCLI(t *testing.T) {
	isolateAgentEnv(t)
	home := t.TempDir()
	require.NoError(t, copyDir(
		filepath.Join(fixturesDir(t), "agents", "home", ".gemini", "antigravity"),
		filepath.Join(home, ".gemini", "antigravity"),
	))

	tools := collectTools(t, NewGeminiDiscoverer, DiscoveryConfig{HomeDir: home})
	assert.Empty(t, tools, "~/.gemini/antigravity alone must not report Gemini CLI")
}

func TestCopilotDiscoverer_SkillsDirIsNotCopilotCLI(t *testing.T) {
	isolateAgentEnv(t)
	home := t.TempDir()
	require.NoError(t, mkdir(filepath.Join(home, ".copilot", "skills")))

	tools := collectTools(t, NewCopilotDiscoverer, DiscoveryConfig{HomeDir: home})
	assert.Empty(t, tools, "~/.copilot/skills alone must not report Copilot CLI")
}

func TestCodexDiscoverer_HonorsCodexHome(t *testing.T) {
	isolateAgentEnv(t)
	codexHome := t.TempDir()
	require.NoError(t, copyFile(
		filepath.Join(fixturesDir(t), "agents", "home", ".codex", "config.toml"),
		filepath.Join(codexHome, "config.toml"),
	))
	t.Setenv("CODEX_HOME", codexHome)

	tools := collectTools(t, NewCodexDiscoverer, DiscoveryConfig{HomeDir: t.TempDir()})
	require.NotEmpty(t, tools)
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer {
			assert.Equal(t, filepath.Join(codexHome, "config.toml"), tool.ConfigPath)
		}
	}
}

func TestCodexDiscoverer_ServerDetails(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)

	servers := mcpServersByName(collectTools(t, NewCodexDiscoverer, DiscoveryConfig{HomeDir: home}))

	stdio := servers["codex-stdio"]
	require.NotNil(t, stdio)
	assert.Equal(t, "npx", stdio.MCPServer.Command)
	assert.Contains(t, stdio.MCPServer.Args, "--api-key=<REDACTED>")
	assert.NotContains(t, stdio.MCPServer.Args, "--api-key=secret123")
	assert.Equal(t, []string{"EXAMPLE_TOKEN", "PASSTHROUGH_VAR", "SOURCED_VAR"}, stdio.MCPServer.EnvVarNames)
	assert.Equal(t, []string{"search"}, stdio.MCPServer.AllowedTools)
	assert.Nil(t, stdio.Enabled)

	remote := servers["codex-remote"]
	require.NotNil(t, remote)
	assert.Equal(t, "https://example.com/mcp", remote.MCPServer.URL)
	assert.Equal(t, []string{"X-Api-Key", "X-Org"}, remote.MCPServer.HeaderNames)
	assert.Equal(t, []string{"API_KEY_VAR", "REMOTE_TOKEN"}, remote.MCPServer.EnvVarNames)
	require.NotNil(t, remote.Enabled)
	assert.False(t, *remote.Enabled)
}

func TestOpenCodeDiscoverer_ServerDetails(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)

	servers := mcpServersByName(collectTools(t, NewOpenCodeDiscoverer, DiscoveryConfig{HomeDir: home}))

	local := servers["opencode-local"]
	require.NotNil(t, local)
	assert.Equal(t, "npx", local.MCPServer.Command)
	assert.Equal(t, []string{"-y", "@example/mcp-server"}, local.MCPServer.Args)
	assert.Equal(t, []string{"OPENCODE_TOKEN"}, local.MCPServer.EnvVarNames)
	require.NotNil(t, local.Enabled)
	assert.True(t, *local.Enabled)

	remote := servers["opencode-remote"]
	require.NotNil(t, remote)
	assert.Equal(t, []string{"Authorization"}, remote.MCPServer.HeaderNames)
	require.NotNil(t, remote.Enabled)
	assert.False(t, *remote.Enabled)
}

func TestGooseDiscoverer_ServerDetails(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)

	servers := mcpServersByName(collectTools(t, NewGooseDiscoverer, DiscoveryConfig{HomeDir: home}))

	assert.NotContains(t, servers, "developer", "builtin extensions are not MCP servers")

	stdio := servers["goose-stdio"]
	require.NotNil(t, stdio)
	assert.Equal(t, "npx", stdio.MCPServer.Command)
	assert.Equal(t, []string{"GITHUB_TOKEN", "GOOSE_TOKEN"}, stdio.MCPServer.EnvVarNames)

	remote := servers["goose-http"]
	require.NotNil(t, remote)
	assert.Equal(t, "https://example.com/mcp", remote.MCPServer.URL)
	require.NotNil(t, remote.Enabled)
	assert.False(t, *remote.Enabled)
}

func TestZedDiscoverer_LegacyCommandShape(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)

	servers := mcpServersByName(collectTools(t, NewZedDiscoverer, DiscoveryConfig{HomeDir: home}))

	legacy := servers["zed-legacy"]
	require.NotNil(t, legacy)
	assert.Equal(t, "uvx", legacy.MCPServer.Command)
	assert.Equal(t, []string{"mcp-server-git"}, legacy.MCPServer.Args)

	current := servers["zed-stdio"]
	require.NotNil(t, current)
	assert.Equal(t, "npx", current.MCPServer.Command)
	assert.Equal(t, []string{"ZED_TOKEN"}, current.MCPServer.EnvVarNames)
}

func TestContinueDiscoverer_HeadersFromRequestOptions(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)

	servers := mcpServersByName(collectTools(t, NewContinueDiscoverer, DiscoveryConfig{HomeDir: home}))

	remote := servers["continue-remote"]
	require.NotNil(t, remote)
	assert.Equal(t, []string{"Authorization"}, remote.MCPServer.HeaderNames)
}

func mcpServersByName(tools []*AITool) map[string]*AITool {
	servers := map[string]*AITool{}
	for _, tool := range tools {
		if tool.Type == AIToolTypeMCPServer {
			servers[tool.Name] = tool
		}
	}
	return servers
}

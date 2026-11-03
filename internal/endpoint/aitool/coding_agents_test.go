package aitool

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// isolateAgentEnv clears the environment variables that move the config of
// an agent, so a test sees only the fixture home.
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

func collectTools(t *testing.T, factory AIToolDiscovererFactory, config DiscoveryConfig) []*inventory.Item {
	t.Helper()
	reader, err := factory(config)
	require.NoError(t, err)

	var tools []*inventory.Item
	err = reader.EnumTools(context.Background(), func(tool *inventory.Item) error {
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
	wantSystemMCP        map[string]inventory.Transport
	wantProjectMCP       map[string]inventory.Transport
	wantInstructionFiles []string
}

var codingAgentCases = []codingAgentCase{
	{
		name: "Codex", factory: NewCodexDiscoverer, app: codexApp, appDisplay: codexAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"codex-stdio":  inventory.TransportStdio,
			"codex-remote": inventory.TransportStreamableHTTP,
		},
		wantProjectMCP: map[string]inventory.Transport{"codex-project": inventory.TransportStdio},
	},
	{
		name: "GeminiCLI", factory: NewGeminiDiscoverer, app: geminiApp, appDisplay: geminiAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"gemini-stdio": inventory.TransportStdio,
			"gemini-http":  inventory.TransportStreamableHTTP,
			"gemini-sse":   inventory.TransportSSE,
		},
		wantProjectMCP:       map[string]inventory.Transport{"gemini-project": inventory.TransportStdio},
		wantInstructionFiles: []string{"GEMINI.md"},
	},
	{
		name: "CopilotCLI", factory: NewCopilotDiscoverer, app: copilotApp, appDisplay: copilotAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"copilot-local": inventory.TransportStdio,
			"copilot-http":  inventory.TransportStreamableHTTP,
		},
		wantProjectMCP: map[string]inventory.Transport{"copilot-project": inventory.TransportStdio},
	},
	{
		name: "OpenCode", factory: NewOpenCodeDiscoverer, app: openCodeApp, appDisplay: openCodeAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"opencode-local":  inventory.TransportStdio,
			"opencode-remote": inventory.TransportStreamableHTTP,
		},
		wantProjectMCP: map[string]inventory.Transport{"opencode-project": inventory.TransportStreamableHTTP},
	},
	{
		name: "QwenCode", factory: NewQwenCodeDiscoverer, app: qwenCodeApp, appDisplay: qwenCodeAppDisplay,
		wantAgent:            true,
		wantSystemMCP:        map[string]inventory.Transport{"qwen-stdio": inventory.TransportStdio},
		wantProjectMCP:       map[string]inventory.Transport{"qwen-project": inventory.TransportStreamableHTTP},
		wantInstructionFiles: []string{"QWEN.md"},
	},
	{
		name: "Amp", factory: NewAmpDiscoverer, app: ampApp, appDisplay: ampAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"amp-stdio":  inventory.TransportStdio,
			"amp-remote": inventory.TransportStreamableHTTP,
		},
		wantProjectMCP: map[string]inventory.Transport{"amp-project": inventory.TransportStdio},
	},
	{
		name: "Augment", factory: NewAugmentDiscoverer, app: augmentApp, appDisplay: augmentAppDisplay,
		wantAgent:     true,
		wantSystemMCP: map[string]inventory.Transport{"augment-stdio": inventory.TransportStdio},
	},
	{
		name: "Kiro", factory: NewKiroDiscoverer, app: kiroApp, appDisplay: kiroAppDisplay,
		wantAgent:            true,
		wantSystemMCP:        map[string]inventory.Transport{"kiro-stdio": inventory.TransportStdio},
		wantProjectMCP:       map[string]inventory.Transport{"kiro-project": inventory.TransportStreamableHTTP},
		wantInstructionFiles: []string{"steering"},
	},
	{
		name: "AmazonQ", factory: NewAmazonQConfigDiscoverer, app: amazonQApp, appDisplay: amazonQAppDisplay,
		wantAgent:      true,
		wantSystemMCP:  map[string]inventory.Transport{"amazonq-stdio": inventory.TransportStdio},
		wantProjectMCP: map[string]inventory.Transport{"amazonq-project": inventory.TransportStdio},
	},
	{
		name: "Junie", factory: NewJunieDiscoverer, app: junieApp, appDisplay: junieAppDisplay,
		wantAgent:            true,
		wantSystemMCP:        map[string]inventory.Transport{"junie-stdio": inventory.TransportStdio},
		wantProjectMCP:       map[string]inventory.Transport{"junie-project": inventory.TransportStdio},
		wantInstructionFiles: []string{"guidelines.md"},
	},
	{
		name: "Goose", factory: NewGooseDiscoverer, app: gooseApp, appDisplay: gooseAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"goose-stdio": inventory.TransportStdio,
			"goose-http":  inventory.TransportStreamableHTTP,
		},
		wantInstructionFiles: []string{".goosehints"},
	},
	{
		name: "Continue", factory: NewContinueDiscoverer, app: continueApp, appDisplay: continueAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"continue-sqlite": inventory.TransportStdio,
			"continue-remote": inventory.TransportStreamableHTTP,
		},
		wantProjectMCP: map[string]inventory.Transport{"continue-project": inventory.TransportStdio},
	},
	{
		name: "Zed", factory: NewZedDiscoverer, app: zedApp, appDisplay: zedAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"zed-stdio":  inventory.TransportStdio,
			"zed-legacy": inventory.TransportStdio,
			"zed-remote": inventory.TransportStreamableHTTP,
		},
	},
	{
		name: "Cline", factory: NewClineDiscoverer, app: clineApp, appDisplay: clineAppDisplay,
		wantAgent: true,
		wantSystemMCP: map[string]inventory.Transport{
			"cline-ext-stdio":  inventory.TransportStdio,
			"cline-cli-remote": inventory.TransportSSE,
		},
		wantInstructionFiles: []string{".clinerules"},
	},
	{
		name: "RooCode", factory: NewRooCodeDiscoverer, app: rooCodeApp, appDisplay: rooCodeAppDisplay,
		wantSystemMCP:  map[string]inventory.Transport{"roo-stdio": inventory.TransportStdio},
		wantProjectMCP: map[string]inventory.Transport{"roo-project": inventory.TransportStdio},
	},
}

func TestCodingAgentDiscoverers_WithFixtures(t *testing.T) {
	isolateAgentEnv(t)
	home := agentsFixtureHome(t)
	projectDir := filepath.Join(fixturesDir(t), "agents", "project")

	for _, tc := range codingAgentCases {
		t.Run(tc.name, func(t *testing.T) {
			tools := collectTools(t, tc.factory, DiscoveryConfig{HomeDir: home, ProjectDir: projectDir})

			gotSystemMCP := map[string]inventory.Transport{}
			gotProjectMCP := map[string]inventory.Transport{}
			var agents, projectConfigs []*inventory.Item
			for _, tool := range tools {
				assert.Equal(t, tc.app, tool.App, "tool %s reported under wrong app", tool.Name)
				assert.Equal(t, tc.appDisplay, tool.Metadata[metaKeyAppDisplay])
				assert.NotEmpty(t, tool.ItemIdentity)
				assert.NotEmpty(t, tool.SourceID)

				switch tool.Kind {
				case inventory.KindMCPServer:
					require.NotNil(t, tool.MCPServer)
					if tool.Scope == inventory.ScopeSystem {
						gotSystemMCP[tool.Name] = tool.MCPServer.Transport
					} else {
						gotProjectMCP[tool.Name] = tool.MCPServer.Transport
					}
				case inventory.KindCodingAgent:
					agents = append(agents, tool)
				case inventory.KindProjectConfig:
					projectConfigs = append(projectConfigs, tool)
				default:
					assert.Failf(t, "unexpected item kind", "kind %d", tool.Kind)
				}
			}

			if tc.wantAgent {
				require.Len(t, agents, 1)
				assert.Equal(t, tc.appDisplay, agents[0].Name)
				assert.Equal(t, inventory.ScopeSystem, agents[0].Scope)
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
			assert.Equal(t, inventory.ScopeProject, projectConfigs[0].Scope)
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

	systemOnly, err := NewDiscoveryScope(inventory.ScopeSystem)
	require.NoError(t, err)
	projectOnly, err := NewDiscoveryScope(inventory.ScopeProject)
	require.NoError(t, err)

	for _, tc := range codingAgentCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range collectTools(t, tc.factory, DiscoveryConfig{HomeDir: home, ProjectDir: projectDir, Scope: systemOnly}) {
				assert.Equal(t, inventory.ScopeSystem, tool.Scope)
			}
			for _, tool := range collectTools(t, tc.factory, DiscoveryConfig{HomeDir: home, ProjectDir: projectDir, Scope: projectOnly}) {
				assert.Equal(t, inventory.ScopeProject, tool.Scope)
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
	own := t.TempDir()
	t.Setenv("HOME", own)
	t.Setenv("USERPROFILE", own)

	tools := collectTools(t, NewCodexDiscoverer, DiscoveryConfig{HomeDir: own})
	require.NotEmpty(t, tools)
	for _, tool := range tools {
		if tool.Kind == inventory.KindMCPServer {
			assert.Equal(t, filepath.Join(codexHome, "config.toml"), tool.ConfigPath)
		}
	}
}

func TestOwnHomeComparesFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link needs a privilege on Windows")
	}
	own := t.TempDir()
	t.Setenv("HOME", own)
	t.Setenv("USERPROFILE", own)
	link := filepath.Join(t.TempDir(), "home-link")
	require.NoError(t, os.Symlink(own, link))

	assert.True(t, ownHome(DiscoveryConfig{}))
	assert.True(t, ownHome(DiscoveryConfig{HomeDir: link}), "another path to the same folder is the own home")
	assert.False(t, ownHome(DiscoveryConfig{HomeDir: t.TempDir()}))
}

func TestProjectConfigsInAFolderWithGlobCharacters(t *testing.T) {
	isolateAgentEnv(t)
	project := filepath.Join(t.TempDir(), "app[1]")
	require.NoError(t, copyDir(filepath.Join(fixturesDir(t), "agents", "project"), project))

	var paths []string
	for _, tool := range collectTools(t, NewCodexDiscoverer, DiscoveryConfig{HomeDir: t.TempDir(), ProjectDir: project}) {
		if tool.Kind == inventory.KindMCPServer {
			paths = append(paths, tool.ConfigPath)
		}
	}
	assert.Contains(t, paths, filepath.Join(project, ".codex", "config.toml"), "a [ in the folder name is not a wildcard")
}

// TestAppDataPathOfAnotherHome guards --all-users on Windows: the APPDATA of
// the user who runs vet is not the folder of another user.
func TestAppDataPathOfAnotherHome(t *testing.T) {
	own := t.TempDir()
	t.Setenv("HOME", own)
	t.Setenv("USERPROFILE", own)
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)
	other := t.TempDir()

	assert.Equal(t, filepath.Join(appData, "Zed"), appDataPath(DiscoveryConfig{HomeDir: own}, own, "Zed"))
	want := ""
	if runtime.GOOS == "windows" {
		want = filepath.Join(other, "AppData", "Roaming", "Zed")
	}
	assert.Equal(t, want, appDataPath(DiscoveryConfig{HomeDir: other}, other, "Zed"))
}

// TestConfigHomeVariablesApplyToTheOwnHomeOnly guards --all-users: the
// CODEX_HOME and COPILOT_HOME of the user who runs vet must not replace the
// folder of another user.
func TestConfigHomeVariablesApplyToTheOwnHomeOnly(t *testing.T) {
	isolateAgentEnv(t)
	own := t.TempDir()
	t.Setenv("HOME", own)
	t.Setenv("USERPROFILE", own)
	t.Setenv("CODEX_HOME", t.TempDir())
	t.Setenv("COPILOT_HOME", t.TempDir())
	other := agentsFixtureHome(t)

	for _, tc := range []struct {
		name    string
		factory AIToolDiscovererFactory
		file    string
	}{
		{"codex", NewCodexDiscoverer, filepath.Join(".codex", "config.toml")},
		{"copilot", NewCopilotDiscoverer, filepath.Join(".copilot", "mcp-config.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			for _, tool := range collectTools(t, tc.factory, DiscoveryConfig{HomeDir: other}) {
				if tool.Kind == inventory.KindMCPServer {
					paths = append(paths, tool.ConfigPath)
				}
			}
			assert.Contains(t, paths, filepath.Join(other, tc.file), "vet reads the folder of the other user")
		})
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

func mcpServersByName(tools []*inventory.Item) map[string]*inventory.Item {
	servers := map[string]*inventory.Item{}
	for _, tool := range tools {
		if tool.Kind == inventory.KindMCPServer {
			servers[tool.Name] = tool
		}
	}
	return servers
}

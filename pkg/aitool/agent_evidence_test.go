package aitool

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func evidenceTestAgent(app string) *AITool {
	return newCodingAgent(app, app, "/home/user/."+app)
}

func evidenceTestCLI(app string, verified bool) *AITool {
	tool := &AITool{Name: app, Type: AIToolTypeCLITool, Scope: AIToolScopeSystem, App: app}
	tool.SetMeta("binary.verified", verified)
	return tool
}

func evidenceTestExtension(id string) *AITool {
	return &AITool{
		Name:      id,
		Type:      AIToolTypeAIExtension,
		Scope:     AIToolScopeSystem,
		App:       ideExtensionsApp,
		Extension: &ExtensionConfig{ID: id},
	}
}

// discoverWith runs the given tools through Registry.Discover, one reader
// per tool, so they arrive in registration order like real discoverers.
func discoverWith(t *testing.T, tools ...*AITool) []*AITool {
	t.Helper()
	r := NewRegistry()
	for _, tool := range tools {
		r.Register(tool.Name, func(_ DiscoveryConfig) (AIToolReader, error) {
			return &mockReader{name: tool.Name, app: tool.App, tools: []*AITool{tool}}, nil
		})
	}

	var out []*AITool
	require.NoError(t, r.Discover(context.Background(), DiscoveryConfig{}, func(tool *AITool) error {
		out = append(out, tool)
		return nil
	}))
	return out
}

func agentByApp(t *testing.T, tools []*AITool, app string) *AITool {
	t.Helper()
	for _, tool := range tools {
		if tool.Type == AIToolTypeCodingAgent && tool.App == app {
			return tool
		}
	}
	require.Failf(t, "coding agent not found", "app %s", app)
	return nil
}

func TestInstallEvidence(t *testing.T) {
	withBundle := evidenceTestAgent(zedApp)
	withBundle.InstallPath = "/Applications/Zed.app"

	cases := []struct {
		name          string
		tools         []*AITool
		app           string
		wantInstalled bool
		wantEvidence  string
	}{
		{
			name:         "ConfigOnly",
			tools:        []*AITool{evidenceTestAgent(geminiApp)},
			app:          geminiApp,
			wantEvidence: "config",
		},
		{
			name:          "VerifiedBinary",
			tools:         []*AITool{evidenceTestAgent(codexApp), evidenceTestCLI(codexApp, true)},
			app:           codexApp,
			wantInstalled: true,
			wantEvidence:  "binary,config",
		},
		{
			name:         "UnverifiedBinaryIgnored",
			tools:        []*AITool{evidenceTestAgent(codexApp), evidenceTestCLI(codexApp, false)},
			app:          codexApp,
			wantEvidence: "config",
		},
		{
			name:          "Extension",
			tools:         []*AITool{evidenceTestAgent(clineApp), evidenceTestExtension("saoudrizwan.claude-dev")},
			app:           clineApp,
			wantInstalled: true,
			wantEvidence:  "config,extension",
		},
		{
			name:          "ExtensionIDCaseInsensitive",
			tools:         []*AITool{evidenceTestAgent(augmentApp), evidenceTestExtension("Augment.vscode-augment")},
			app:           augmentApp,
			wantInstalled: true,
			wantEvidence:  "config,extension",
		},
		{
			name:          "AppBundle",
			tools:         []*AITool{withBundle},
			app:           zedApp,
			wantInstalled: true,
			wantEvidence:  "app_bundle,config",
		},
		{
			name: "AllEvidence",
			tools: []*AITool{
				evidenceTestAgent(claudeCodeApp),
				evidenceTestCLI(claudeCodeApp, true),
				evidenceTestExtension("anthropic.claude-code"),
			},
			app:           claudeCodeApp,
			wantInstalled: true,
			wantEvidence:  "binary,config,extension",
		},
		{
			name: "OtherAppsEvidenceDoesNotCrossContaminate",
			tools: []*AITool{
				evidenceTestAgent(geminiApp),
				evidenceTestCLI(codexApp, true),
				evidenceTestExtension("saoudrizwan.claude-dev"),
				// Gemini Code Assist is a different product from Gemini CLI.
				evidenceTestExtension("google.geminicodeassist"),
			},
			app:          geminiApp,
			wantEvidence: "config",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := agentByApp(t, discoverWith(t, tc.tools...), tc.app)
			assert.Equal(t, tc.wantInstalled, agent.GetMeta(MetaAgentInstalled))
			assert.Equal(t, tc.wantEvidence, agent.GetMeta(MetaAgentEvidence))
		})
	}
}

func TestRegistry_CodingAgentsEmittedAfterEvidence(t *testing.T) {
	// The agent is registered before the CLI discoverer, as in DefaultRegistry.
	tools := discoverWith(t, evidenceTestAgent(codexApp), evidenceTestCLI(codexApp, true))

	require.Len(t, tools, 2)
	assert.Equal(t, AIToolTypeCLITool, tools[0].Type)
	assert.Equal(t, AIToolTypeCodingAgent, tools[1].Type)
	assert.Equal(t, true, tools[1].GetMeta(MetaAgentInstalled))
}

func TestRegistry_NonAgentToolsGetNoEvidence(t *testing.T) {
	for _, tool := range discoverWith(t, evidenceTestCLI(codexApp, true), evidenceTestExtension("openai.chatgpt")) {
		assert.Nil(t, tool.GetMeta(MetaAgentInstalled))
		assert.Nil(t, tool.GetMeta(MetaAgentEvidence))
	}
}

func TestRegistry_AgentHandlerErrorPropagated(t *testing.T) {
	r := NewRegistry()
	r.Register("agent", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{name: "agent", tools: []*AITool{evidenceTestAgent(codexApp)}}, nil
	})

	handlerErr := errors.New("handler error")
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(*AITool) error { return handlerErr })
	assert.ErrorIs(t, err, handlerErr)
}

func TestInstallMarkers_SetInstallPath(t *testing.T) {
	isolateAgentEnv(t)

	t.Run("GooseCLIInstall", func(t *testing.T) {
		home := agentsFixtureHome(t)
		goosePath := filepath.Join(home, ".local", "bin", "goose")
		require.NoError(t, mkdir(filepath.Dir(goosePath)))
		require.NoError(t, copyFile(filepath.Join(home, ".config", "goose", "config.yaml"), goosePath))

		agent := agentByApp(t, collectTools(t, NewGooseDiscoverer, DiscoveryConfig{HomeDir: home}), gooseApp)
		assert.Equal(t, goosePath, agent.InstallPath)
	})

	t.Run("ZedLinuxInstallScript", func(t *testing.T) {
		home := agentsFixtureHome(t)
		zedInstall := filepath.Join(home, ".local", "zed.app")
		require.NoError(t, mkdir(zedInstall))

		agent := agentByApp(t, collectTools(t, NewZedDiscoverer, DiscoveryConfig{HomeDir: home}), zedApp)
		assert.Equal(t, zedInstall, agent.InstallPath)
	})

	t.Run("NoInstallLocation", func(t *testing.T) {
		home := agentsFixtureHome(t)

		agent := agentByApp(t, collectTools(t, NewGooseDiscoverer, DiscoveryConfig{HomeDir: home}), gooseApp)
		assert.Empty(t, agent.InstallPath)
	})
}

func TestEnvPath_UnsetReturnsEmpty(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	assert.Empty(t, envPath("LOCALAPPDATA", "Programs", "Microsoft VS Code"))

	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	assert.Equal(t, filepath.Join(base, "Programs", "Microsoft VS Code"),
		envPath("LOCALAPPDATA", "Programs", "Microsoft VS Code"))
}

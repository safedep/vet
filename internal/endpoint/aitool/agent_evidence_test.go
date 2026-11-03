package aitool

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

func evidenceTestAgent(app string) *inventory.Item {
	return newCodingAgent(app, app, "/home/user/."+app)
}

func evidenceTestCLI(app string, verified bool) *inventory.Item {
	it := newItem(inventory.KindCLITool, inventory.ScopeSystem, app, app, app, "/usr/bin/"+app)
	if verified {
		it.SetMeta(metaKeyBinaryVerified, "true")
	}
	return it
}

func evidenceTestExtension(id string) *inventory.Item {
	it := newItem(inventory.KindAIExtension, inventory.ScopeSystem, ideExtensionsApp, "VS Code", id, "/home/user/.vscode/extensions/extensions.json")
	it.SetMeta(metaKeyExtensionID, id)
	return it
}

// discoverWith runs each item through Registry.Discover with one reader for
// each item, so the items come in registration order as from real
// discoverers.
func discoverWith(t *testing.T, items ...*inventory.Item) []*inventory.Item {
	t.Helper()
	r := NewRegistry()
	for _, it := range items {
		r.Register(it.Name, func(_ DiscoveryConfig) (AIToolReader, error) {
			return &mockReader{name: it.Name, app: it.App, tools: []*inventory.Item{it}}, nil
		})
	}

	var out []*inventory.Item
	require.NoError(t, r.Discover(context.Background(), DiscoveryConfig{}, func(it *inventory.Item) error {
		out = append(out, it)
		return nil
	}))
	return out
}

func agentByApp(t *testing.T, items []*inventory.Item, app string) *inventory.Item {
	t.Helper()
	for _, it := range items {
		if it.Kind == inventory.KindCodingAgent && it.App == app {
			return it
		}
	}
	require.Failf(t, "coding agent not found", "app %s", app)
	return nil
}

func TestInstallEvidence(t *testing.T) {
	withBundle := evidenceTestAgent(zedApp)
	addAgentEvidence(withBundle, agentEvidenceAppBundle)

	cases := []struct {
		name          string
		items         []*inventory.Item
		app           string
		wantInstalled string
		wantEvidence  string
	}{
		{
			name:          "ConfigOnly",
			items:         []*inventory.Item{evidenceTestAgent(geminiApp)},
			app:           geminiApp,
			wantInstalled: "false",
			wantEvidence:  "config",
		},
		{
			name:          "VerifiedBinary",
			items:         []*inventory.Item{evidenceTestAgent(codexApp), evidenceTestCLI(codexApp, true)},
			app:           codexApp,
			wantInstalled: "true",
			wantEvidence:  "binary,config",
		},
		{
			name:          "UnverifiedBinaryIgnored",
			items:         []*inventory.Item{evidenceTestAgent(codexApp), evidenceTestCLI(codexApp, false)},
			app:           codexApp,
			wantInstalled: "false",
			wantEvidence:  "config",
		},
		{
			name:          "Extension",
			items:         []*inventory.Item{evidenceTestAgent(clineApp), evidenceTestExtension("saoudrizwan.claude-dev")},
			app:           clineApp,
			wantInstalled: "true",
			wantEvidence:  "config,extension",
		},
		{
			name:          "ExtensionIDCaseInsensitive",
			items:         []*inventory.Item{evidenceTestAgent(augmentApp), evidenceTestExtension("Augment.vscode-augment")},
			app:           augmentApp,
			wantInstalled: "true",
			wantEvidence:  "config,extension",
		},
		{
			name:          "AppBundle",
			items:         []*inventory.Item{withBundle},
			app:           zedApp,
			wantInstalled: "true",
			wantEvidence:  "app_bundle,config",
		},
		{
			name: "AllEvidence",
			items: []*inventory.Item{
				evidenceTestAgent(claudeCodeApp),
				evidenceTestCLI(claudeCodeApp, true),
				evidenceTestExtension("anthropic.claude-code"),
			},
			app:           claudeCodeApp,
			wantInstalled: "true",
			wantEvidence:  "binary,config,extension",
		},
		{
			name: "OtherAppsEvidenceDoesNotCrossContaminate",
			items: []*inventory.Item{
				evidenceTestAgent(geminiApp),
				evidenceTestCLI(codexApp, true),
				evidenceTestExtension("saoudrizwan.claude-dev"),
				// Gemini Code Assist is not the same product as Gemini CLI.
				evidenceTestExtension("google.geminicodeassist"),
			},
			app:           geminiApp,
			wantInstalled: "false",
			wantEvidence:  "config",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := agentByApp(t, discoverWith(t, tc.items...), tc.app)
			assert.Equal(t, tc.wantInstalled, agent.Metadata[metaKeyAgentInstalled])
			assert.Equal(t, tc.wantEvidence, agent.Metadata[metaKeyAgentEvidence])
		})
	}
}

func TestRegistry_CodingAgentsEmittedAfterEvidence(t *testing.T) {
	// The agent comes before the CLI discoverer, as in DefaultRegistry.
	items := discoverWith(t, evidenceTestAgent(codexApp), evidenceTestCLI(codexApp, true))

	require.Len(t, items, 2)
	assert.Equal(t, inventory.KindCLITool, items[0].Kind)
	assert.Equal(t, inventory.KindCodingAgent, items[1].Kind)
	assert.Equal(t, "true", items[1].Metadata[metaKeyAgentInstalled])
}

func TestRegistry_NonAgentToolsGetNoEvidence(t *testing.T) {
	for _, it := range discoverWith(t, evidenceTestCLI(codexApp, true), evidenceTestExtension("openai.chatgpt")) {
		assert.NotContains(t, it.Metadata, metaKeyAgentInstalled)
		assert.NotContains(t, it.Metadata, metaKeyAgentEvidence)
	}
}

func TestRegistry_AgentHandlerErrorPropagated(t *testing.T) {
	r := NewRegistry()
	r.Register("agent", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{name: "agent", tools: []*inventory.Item{evidenceTestAgent(codexApp)}}, nil
	})

	handlerErr := errors.New("handler error")
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(*inventory.Item) error { return handlerErr })
	assert.ErrorIs(t, err, handlerErr)
}

func TestInstallMarkers_AddAppBundleEvidence(t *testing.T) {
	isolateAgentEnv(t)

	tests := []struct {
		name    string
		factory AIToolDiscovererFactory
		app     string
		install func(home string) error
		want    string
	}{
		{
			name: "GooseCLIInstall", factory: NewGooseDiscoverer, app: gooseApp,
			install: func(home string) error {
				goosePath := filepath.Join(home, ".local", "bin", "goose")
				if err := mkdir(filepath.Dir(goosePath)); err != nil {
					return err
				}
				return copyFile(filepath.Join(home, ".config", "goose", "config.yaml"), goosePath)
			},
			want: agentEvidenceAppBundle,
		},
		{
			name: "ZedLinuxInstallScript", factory: NewZedDiscoverer, app: zedApp,
			install: func(home string) error { return mkdir(filepath.Join(home, ".local", "zed.app")) },
			want:    agentEvidenceAppBundle,
		},
		{
			name: "NoInstallLocation", factory: NewGooseDiscoverer, app: gooseApp,
			install: func(string) error { return nil },
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := agentsFixtureHome(t)
			require.NoError(t, tt.install(home))

			agent := agentByApp(t, collectTools(t, tt.factory, DiscoveryConfig{HomeDir: home}), tt.app)
			assert.Equal(t, tt.want, agent.Metadata[metaKeyAgentEvidence])
		})
	}
}

func TestEnvPath_UnsetReturnsEmpty(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	assert.Empty(t, envPath("LOCALAPPDATA", "Programs", "Microsoft VS Code"))

	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	assert.Equal(t, filepath.Join(base, "Programs", "Microsoft VS Code"),
		envPath("LOCALAPPDATA", "Programs", "Microsoft VS Code"))
}

type failingReader struct{ err error }

func (failingReader) Name() string { return "failing" }
func (failingReader) App() string  { return "failing" }
func (f failingReader) EnumTools(context.Context, AIToolHandlerFn) error {
	return f.err
}

func TestRegistry_DiscovererErrorKeepsTheAgentsBeforeIt(t *testing.T) {
	r := NewRegistry()
	r.Register("agent", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{name: "agent", tools: []*inventory.Item{evidenceTestAgent(codexApp)}}, nil
	})
	enumErr := errors.New("enum error")
	r.Register("failing", func(_ DiscoveryConfig) (AIToolReader, error) { return failingReader{err: enumErr}, nil })

	var got []*inventory.Item
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(it *inventory.Item) error {
		got = append(got, it)
		return nil
	})
	assert.ErrorIs(t, err, enumErr)
	require.Len(t, got, 1, "an agent found before the error still reaches the handler")
	assert.Equal(t, inventory.KindCodingAgent, got[0].Kind)
}

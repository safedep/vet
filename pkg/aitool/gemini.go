package aitool

import "path/filepath"

const (
	geminiApp        = "gemini_cli"
	geminiAppDisplay = "Gemini CLI"
)

// NewGeminiDiscoverer creates a Gemini CLI config discoverer.
func NewGeminiDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	// ~/.gemini is shared with Antigravity (~/.gemini/antigravity), so the
	// directory alone does not prove Gemini CLI is installed; settings.json does.
	settingsPath := filepath.Join(homeDir, ".gemini", "settings.json")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:              geminiApp,
		appDisplay:       geminiAppDisplay,
		agentMarkers:     []string{settingsPath},
		systemMCPPaths:   []string{settingsPath},
		projectMCPGlobs:  []string{filepath.Join(".gemini", "settings.json")},
		instructionFiles: []string{"GEMINI.md"},
	}), nil
}

package aitool

import "path/filepath"

const (
	geminiApp        = "gemini_cli"
	geminiAppDisplay = "Gemini CLI"
)

// NewGeminiDiscoverer creates a Gemini CLI config discoverer.
func NewGeminiDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	// Antigravity also writes to ~/.gemini, in ~/.gemini/antigravity. So
	// settings.json, not the folder, shows that Gemini CLI is set up.
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

package aitool

import "path/filepath"

const (
	qwenCodeApp        = "qwen_code"
	qwenCodeAppDisplay = "Qwen Code"
)

// NewQwenCodeDiscoverer creates a Qwen Code config discoverer. Qwen Code is a
// fork of Gemini CLI and has the same settings.json layout.
func NewQwenCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	qwenDir := filepath.Join(homeDir, ".qwen")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:              qwenCodeApp,
		appDisplay:       qwenCodeAppDisplay,
		agentMarkers:     []string{qwenDir},
		systemMCPPaths:   []string{filepath.Join(qwenDir, "settings.json")},
		projectMCPGlobs:  []string{filepath.Join(".qwen", "settings.json")},
		instructionFiles: []string{"QWEN.md"},
	}), nil
}

package aitool

import "path/filepath"

const (
	qwenCodeApp        = "qwen_code"
	qwenCodeAppDisplay = "Qwen Code"
)

// NewQwenCodeDiscoverer creates a Qwen Code config discoverer. Qwen Code is a
// Gemini CLI fork and shares its settings.json layout.
func NewQwenCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
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

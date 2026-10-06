package aitool

import "path/filepath"

const (
	kiroApp        = "kiro"
	kiroAppDisplay = "Kiro"
)

// NewKiroDiscoverer creates a Kiro (IDE and CLI) config discoverer.
func NewKiroDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	kiroDir := filepath.Join(homeDir, ".kiro")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:              kiroApp,
		appDisplay:       kiroAppDisplay,
		agentMarkers:     []string{kiroDir},
		installMarkers:   []string{unixPath("Applications", "Kiro.app")},
		systemMCPPaths:   []string{filepath.Join(kiroDir, "settings", "mcp.json")},
		projectMCPGlobs:  []string{filepath.Join(".kiro", "settings", "mcp.json")},
		instructionFiles: []string{filepath.Join(".kiro", "steering")},
	}), nil
}

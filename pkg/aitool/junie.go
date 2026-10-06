package aitool

import "path/filepath"

const (
	junieApp        = "junie"
	junieAppDisplay = "Junie"
)

// NewJunieDiscoverer creates a JetBrains Junie (IDE plugin and CLI) config discoverer.
func NewJunieDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	junieDir := filepath.Join(homeDir, ".junie")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:              junieApp,
		appDisplay:       junieAppDisplay,
		agentMarkers:     []string{junieDir},
		systemMCPPaths:   []string{filepath.Join(junieDir, "mcp", "mcp.json")},
		projectMCPGlobs:  []string{filepath.Join(".junie", "mcp", "mcp.json")},
		instructionFiles: []string{filepath.Join(".junie", "guidelines.md")},
	}), nil
}

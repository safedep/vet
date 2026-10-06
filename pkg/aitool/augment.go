package aitool

import "path/filepath"

const (
	augmentApp        = "augment"
	augmentAppDisplay = "Augment Code"
)

// NewAugmentDiscoverer creates a config discoverer for Augment Code's Auggie CLI.
func NewAugmentDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	augmentDir := filepath.Join(homeDir, ".augment")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:            augmentApp,
		appDisplay:     augmentAppDisplay,
		agentMarkers:   []string{augmentDir},
		systemMCPPaths: []string{filepath.Join(augmentDir, "settings.json")},
	}), nil
}

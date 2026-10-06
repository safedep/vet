package aitool

import "path/filepath"

const amazonQAppDisplay = "Amazon Q"

// NewAmazonQConfigDiscoverer creates an Amazon Q Developer config discoverer.
// It shares the amazon_q app id with the CLI discoverer so both signals group
// under one application.
func NewAmazonQConfigDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	amazonQDir := filepath.Join(homeDir, ".aws", "amazonq")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:             amazonQApp,
		appDisplay:      amazonQAppDisplay,
		agentMarkers:    []string{amazonQDir},
		systemMCPPaths:  []string{filepath.Join(amazonQDir, "mcp.json")},
		projectMCPGlobs: []string{filepath.Join(".amazonq", "mcp.json")},
	}), nil
}

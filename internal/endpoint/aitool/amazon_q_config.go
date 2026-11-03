package aitool

import "path/filepath"

const amazonQAppDisplay = "Amazon Q"

// NewAmazonQConfigDiscoverer creates an Amazon Q Developer config discoverer.
// It uses the app of the CLI discoverer, so the config and the binary of
// Amazon Q are one app.
func NewAmazonQConfigDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
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

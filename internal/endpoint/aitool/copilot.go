package aitool

import "path/filepath"

const (
	copilotApp        = "copilot_cli"
	copilotAppDisplay = "Copilot CLI"
)

// NewCopilotDiscoverer creates a config discoverer for the standalone
// GitHub Copilot CLI (`copilot`). It is not the deprecated gh extension.
func NewCopilotDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	copilotDir := envDirOr(config, "COPILOT_HOME", filepath.Join(homeDir, ".copilot"))

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:        copilotApp,
		appDisplay: copilotAppDisplay,
		// Copilot in VS Code also reads ~/.copilot/skills. Only the CLI
		// writes these files.
		agentMarkers: []string{
			filepath.Join(copilotDir, "config.json"),
			filepath.Join(copilotDir, "settings.json"),
		},
		systemMCPPaths:  []string{filepath.Join(copilotDir, "mcp-config.json")},
		projectMCPGlobs: []string{filepath.Join(".github", "mcp.json")},
	}), nil
}

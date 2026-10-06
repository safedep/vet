package aitool

import "path/filepath"

const (
	copilotApp        = "copilot_cli"
	copilotAppDisplay = "Copilot CLI"
)

// NewCopilotDiscoverer creates a config discoverer for the standalone
// GitHub Copilot CLI (`copilot`), distinct from the deprecated gh extension.
func NewCopilotDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	copilotDir := envDirOr("COPILOT_HOME", filepath.Join(homeDir, ".copilot"))

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:        copilotApp,
		appDisplay: copilotAppDisplay,
		// ~/.copilot/skills is also read by Copilot in VS Code, so key the
		// agent on files only the CLI writes.
		agentMarkers: []string{
			filepath.Join(copilotDir, "config.json"),
			filepath.Join(copilotDir, "settings.json"),
		},
		systemMCPPaths:  []string{filepath.Join(copilotDir, "mcp-config.json")},
		projectMCPGlobs: []string{filepath.Join(".github", "mcp.json")},
	}), nil
}

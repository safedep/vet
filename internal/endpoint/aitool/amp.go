package aitool

import "path/filepath"

const (
	ampApp        = "amp"
	ampAppDisplay = "Amp"
)

// ampSettings is the part of the Amp settings.json that discovery reads.
// Amp puts a prefix on its keys, so the MCP servers are in "amp.mcpServers".
type ampSettings struct {
	MCPServers map[string]mcpServerEntry `json:"amp.mcpServers"`
}

// NewAmpDiscoverer creates an Amp CLI config discoverer.
func NewAmpDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	// Amp uses ~/.config/amp on each OS. On Windows it is %USERPROFILE%\.config\amp.
	ampDir := filepath.Join(homeDir, ".config", "amp")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:          ampApp,
		appDisplay:   ampAppDisplay,
		agentMarkers: []string{ampDir},
		systemMCPPaths: []string{
			filepath.Join(ampDir, "settings.json"),
			filepath.Join(ampDir, "settings.jsonc"),
		},
		projectMCPGlobs: []string{filepath.Join(".amp", "settings.json")},
		parse:           parseAmpSettings,
	}), nil
}

func parseAmpSettings(path string) (*mcpAppConfig, error) {
	var settings ampSettings
	if err := parseJSONCFile(path, &settings); err != nil {
		return nil, err
	}
	return &mcpAppConfig{MCPServers: settings.MCPServers}, nil
}

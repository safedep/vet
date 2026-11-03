package aitool

import "path/filepath"

const (
	clineApp        = "cline"
	clineAppDisplay = "Cline"

	rooCodeApp        = "roo_code"
	rooCodeAppDisplay = "Roo Code"
)

// NewClineDiscoverer creates a discoverer for the MCP settings of Cline. The
// VS Code extension keeps them in its globalStorage, and the Cline CLI keeps
// them in ~/.cline. The AI extension discoverer reports the extension.
func NewClineDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	clineDir := filepath.Join(homeDir, ".cline")
	settingsFile := filepath.Join("settings", "cline_mcp_settings.json")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:          clineApp,
		appDisplay:   clineAppDisplay,
		agentMarkers: []string{clineDir},
		systemMCPPaths: append(
			vscodeGlobalStoragePaths(homeDir, "saoudrizwan.claude-dev", settingsFile),
			filepath.Join(clineDir, "data", settingsFile),
		),
		instructionFiles: []string{".clinerules"},
	}), nil
}

// NewRooCodeDiscoverer creates a discoverer for the MCP settings of Roo Code.
// The AI extension discoverer reports the extension.
func NewRooCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:        rooCodeApp,
		appDisplay: rooCodeAppDisplay,
		systemMCPPaths: vscodeGlobalStoragePaths(homeDir, "rooveterinaryinc.roo-cline",
			filepath.Join("settings", "mcp_settings.json")),
		projectMCPGlobs:  []string{filepath.Join(".roo", "mcp.json")},
		instructionFiles: []string{".roorules", filepath.Join(".roo", "rules")},
	}), nil
}

// vscodeGlobalStoragePaths returns rel in the VS Code globalStorage folder
// of extensionID, for the VS Code user data folder of each OS.
func vscodeGlobalStoragePaths(homeDir, extensionID, rel string) []string {
	var paths []string
	for _, dir := range vscodeUserDataDirs(homeDir) {
		if dir == "" {
			continue
		}
		paths = append(paths, filepath.Join(dir, "globalStorage", extensionID, rel))
	}
	return paths
}

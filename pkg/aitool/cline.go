package aitool

import "path/filepath"

const (
	clineApp        = "cline"
	clineAppDisplay = "Cline"

	rooCodeApp        = "roo_code"
	rooCodeAppDisplay = "Roo Code"
)

// NewClineDiscoverer creates a discoverer for Cline's MCP settings, kept by
// the VS Code extension in its globalStorage and by the Cline CLI in ~/.cline.
// The extension itself is reported by the AI extension discoverer.
func NewClineDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
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

// NewRooCodeDiscoverer creates a discoverer for Roo Code's MCP settings. The
// extension itself is reported by the AI extension discoverer.
func NewRooCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
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

// vscodeGlobalStoragePaths returns rel inside the VS Code globalStorage
// directory of extensionID, for each per-OS VS Code user-data directory.
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

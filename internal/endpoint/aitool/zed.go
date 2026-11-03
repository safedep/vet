package aitool

import (
	"encoding/json"
	"path/filepath"
)

const (
	zedApp        = "zed"
	zedAppDisplay = "Zed"
)

// zedContextServer is one entry under "context_servers" in the Zed settings.
// Old Zed releases nest the command as {"command": {"path", "args", "env"}}.
// Command stays raw, so the parser reads both shapes.
type zedContextServer struct {
	Command json.RawMessage `json:"command,omitempty"`
	Args    []string        `json:"args,omitempty"`
	Env     map[string]any  `json:"env,omitempty"`
	URL     string          `json:"url,omitempty"`
	Headers map[string]any  `json:"headers,omitempty"`
}

type zedLegacyCommand struct {
	Path string         `json:"path"`
	Args []string       `json:"args"`
	Env  map[string]any `json:"env"`
}

type zedSettings struct {
	ContextServers map[string]zedContextServer `json:"context_servers"`
}

// NewZedDiscoverer creates a Zed editor config discoverer. Zed calls an MCP
// server a "context server".
func NewZedDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
	if err != nil {
		return nil, err
	}

	// ~/.config/zed on Linux and macOS, %APPDATA%\Zed on Windows.
	zedDirs := []string{
		filepath.Join(homeDir, ".config", "zed"),
		appDataPath(config, homeDir, "Zed"),
	}

	var settingsPaths []string
	for _, dir := range zedDirs {
		if dir != "" {
			settingsPaths = append(settingsPaths, filepath.Join(dir, "settings.json"))
		}
	}

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:          zedApp,
		appDisplay:   zedAppDisplay,
		agentMarkers: zedDirs,
		// The Linux install script writes ~/.local/zed.app. macOS has /Applications/Zed.app.
		installMarkers: []string{
			filepath.Join(homeDir, ".local", "zed.app"),
			unixPath("Applications", "Zed.app"),
		},
		systemMCPPaths: settingsPaths,
		parse:          parseZedSettings,
	}), nil
}

func parseZedSettings(path string) (*mcpAppConfig, error) {
	var settings zedSettings
	if err := parseJSONCFile(path, &settings); err != nil {
		return nil, err
	}

	servers := make(map[string]mcpServerEntry, len(settings.ContextServers))
	for name, srv := range settings.ContextServers {
		entry := mcpServerEntry{
			Args:    srv.Args,
			Env:     srv.Env,
			URL:     srv.URL,
			Headers: srv.Headers,
		}

		var legacy zedLegacyCommand
		if err := json.Unmarshal(srv.Command, &entry.Command); err != nil &&
			json.Unmarshal(srv.Command, &legacy) == nil {
			entry.Command = legacy.Path
			entry.Args = legacy.Args
			entry.Env = legacy.Env
		}

		servers[name] = entry
	}

	return &mcpAppConfig{MCPServers: servers}, nil
}

package aitool

import "path/filepath"

const (
	openCodeApp        = "opencode"
	openCodeAppDisplay = "OpenCode"
)

// openCodeMCPServer is one entry under "mcp" in opencode.json. Local servers
// carry the executable and its arguments together in a single command array.
type openCodeMCPServer struct {
	Type        string         `json:"type"`
	Command     []string       `json:"command"`
	Environment map[string]any `json:"environment"`
	URL         string         `json:"url"`
	Headers     map[string]any `json:"headers"`
	Enabled     *bool          `json:"enabled"`
}

type openCodeConfig struct {
	MCP map[string]openCodeMCPServer `json:"mcp"`
}

// NewOpenCodeDiscoverer creates an OpenCode config discoverer.
func NewOpenCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	// OpenCode uses ~/.config/opencode on every OS.
	openCodeDir := filepath.Join(homeDir, ".config", "opencode")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:          openCodeApp,
		appDisplay:   openCodeAppDisplay,
		agentMarkers: []string{openCodeDir},
		systemMCPPaths: []string{
			filepath.Join(openCodeDir, "opencode.json"),
			filepath.Join(openCodeDir, "opencode.jsonc"),
		},
		projectMCPGlobs: []string{"opencode.json", "opencode.jsonc"},
		parse:           parseOpenCodeConfig,
	}), nil
}

func parseOpenCodeConfig(path string) (*mcpAppConfig, error) {
	var cfg openCodeConfig
	if err := parseJSONCFile(path, &cfg); err != nil {
		return nil, err
	}

	servers := make(map[string]mcpServerEntry, len(cfg.MCP))
	for name, srv := range cfg.MCP {
		entry := mcpServerEntry{
			Env:     srv.Environment,
			URL:     srv.URL,
			Headers: srv.Headers,
		}
		if srv.Type == "local" {
			entry.Type = "stdio"
		}
		if len(srv.Command) > 0 {
			entry.Command = srv.Command[0]
			entry.Args = srv.Command[1:]
		}
		if srv.Enabled != nil {
			disabled := !*srv.Enabled
			entry.Disabled = &disabled
		}
		servers[name] = entry
	}

	return &mcpAppConfig{MCPServers: servers}, nil
}

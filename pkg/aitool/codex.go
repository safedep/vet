package aitool

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	codexApp        = "codex"
	codexAppDisplay = "Codex"
)

// codexMCPServer is one [mcp_servers.<name>] table in Codex's config.toml.
// Headers may be literal (http_headers) or read from env vars
// (env_http_headers); only names are kept from either.
type codexMCPServer struct {
	Command           string            `toml:"command"`
	Args              []string          `toml:"args"`
	Env               map[string]any    `toml:"env"`
	EnvVars           []any             `toml:"env_vars"`
	URL               string            `toml:"url"`
	BearerTokenEnvVar string            `toml:"bearer_token_env_var"`
	HTTPHeaders       map[string]any    `toml:"http_headers"`
	EnvHTTPHeaders    map[string]string `toml:"env_http_headers"`
	Enabled           *bool             `toml:"enabled"`
	EnabledTools      []string          `toml:"enabled_tools"`
}

type codexConfig struct {
	MCPServers map[string]codexMCPServer `toml:"mcp_servers"`
}

// NewCodexDiscoverer creates an OpenAI Codex (CLI, IDE extension and app)
// config discoverer.
func NewCodexDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	codexDir := envDirOr("CODEX_HOME", filepath.Join(homeDir, ".codex"))

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:             codexApp,
		appDisplay:      codexAppDisplay,
		agentMarkers:    []string{codexDir},
		systemMCPPaths:  []string{filepath.Join(codexDir, "config.toml")},
		projectMCPGlobs: []string{filepath.Join(".codex", "config.toml")},
		parse:           parseCodexConfig,
	}), nil
}

func parseCodexConfig(path string) (*mcpAppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg codexConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse Codex config file %s: %v", path, err)
		return nil, err
	}

	servers := make(map[string]mcpServerEntry, len(cfg.MCPServers))
	for name, srv := range cfg.MCPServers {
		env := make(map[string]any, len(srv.Env)+len(srv.EnvVars)+1)
		for k, v := range srv.Env {
			env[k] = v
		}
		// env_vars entries are either a bare name or a {name, source} table.
		for _, v := range srv.EnvVars {
			switch ev := v.(type) {
			case string:
				env[ev] = nil
			case map[string]any:
				if n, ok := ev["name"].(string); ok {
					env[n] = nil
				}
			}
		}
		if srv.BearerTokenEnvVar != "" {
			env[srv.BearerTokenEnvVar] = nil
		}

		headers := make(map[string]any, len(srv.HTTPHeaders)+len(srv.EnvHTTPHeaders))
		for k, v := range srv.HTTPHeaders {
			headers[k] = v
		}
		for k, v := range srv.EnvHTTPHeaders {
			headers[k] = nil
			env[v] = nil
		}

		entry := mcpServerEntry{
			Command:      srv.Command,
			Args:         srv.Args,
			Env:          env,
			URL:          srv.URL,
			Headers:      headers,
			AllowedTools: srv.EnabledTools,
		}
		// Codex only speaks streamable HTTP for remote servers.
		if srv.URL != "" && srv.Command == "" {
			entry.Type = "streamable_http"
		}
		if srv.Enabled != nil {
			disabled := !*srv.Enabled
			entry.Disabled = &disabled
		}
		servers[name] = entry
	}

	return &mcpAppConfig{MCPServers: servers}, nil
}

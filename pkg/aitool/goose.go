package aitool

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	gooseApp        = "goose"
	gooseAppDisplay = "Goose"
)

// gooseExtension is one entry under "extensions" in Goose's config.yaml.
// Goose calls MCP servers extensions; env_keys names variables resolved from
// the keyring or environment at launch.
type gooseExtension struct {
	Type    string         `yaml:"type"`
	Cmd     string         `yaml:"cmd"`
	Args    []string       `yaml:"args"`
	Envs    map[string]any `yaml:"envs"`
	EnvKeys []string       `yaml:"env_keys"`
	URI     string         `yaml:"uri"`
	Headers map[string]any `yaml:"headers"`
	Enabled *bool          `yaml:"enabled"`
}

type gooseConfig struct {
	Extensions map[string]gooseExtension `yaml:"extensions"`
}

// gooseMCPExtensionTypes are the extension types backed by an external MCP
// server. Other types (builtin, platform, frontend, ...) run inside Goose.
var gooseMCPExtensionTypes = map[string]bool{
	"stdio":           true,
	"sse":             true,
	"streamable_http": true,
}

// NewGooseDiscoverer creates a Goose (Block) config discoverer.
func NewGooseDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	// Linux/macOS: ~/.config/goose, Windows: %APPDATA%\Block\goose\config
	gooseDirs := []string{
		filepath.Join(homeDir, ".config", "goose"),
		envPath("APPDATA", "Block", "goose", "config"),
	}

	var configPaths []string
	for _, dir := range gooseDirs {
		if dir != "" {
			configPaths = append(configPaths, filepath.Join(dir, "config.yaml"))
		}
	}

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:              gooseApp,
		appDisplay:       gooseAppDisplay,
		agentMarkers:     gooseDirs,
		systemMCPPaths:   configPaths,
		instructionFiles: []string{".goosehints"},
		parse:            parseGooseConfig,
	}), nil
}

func parseGooseConfig(path string) (*mcpAppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg gooseConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse Goose config file %s: %v", path, err)
		return nil, err
	}

	servers := make(map[string]mcpServerEntry, len(cfg.Extensions))
	for name, ext := range cfg.Extensions {
		if !gooseMCPExtensionTypes[ext.Type] {
			continue
		}

		env := make(map[string]any, len(ext.Envs)+len(ext.EnvKeys))
		for k, v := range ext.Envs {
			env[k] = v
		}
		for _, k := range ext.EnvKeys {
			env[k] = nil
		}

		entry := mcpServerEntry{
			Type:    ext.Type,
			Command: ext.Cmd,
			Args:    ext.Args,
			Env:     env,
			URL:     ext.URI,
			Headers: ext.Headers,
		}
		if ext.Enabled != nil {
			disabled := !*ext.Enabled
			entry.Disabled = &disabled
		}
		servers[name] = entry
	}

	return &mcpAppConfig{MCPServers: servers}, nil
}

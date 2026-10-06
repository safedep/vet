package aitool

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	continueApp        = "continue"
	continueAppDisplay = "Continue"
)

// continueMCPServer is one item of the "mcpServers" list in Continue's YAML
// config. Unlike the JSON formats, servers are a list keyed by "name".
type continueMCPServer struct {
	Name           string         `yaml:"name"`
	Type           string         `yaml:"type"`
	Command        string         `yaml:"command"`
	Args           []string       `yaml:"args"`
	Env            map[string]any `yaml:"env"`
	URL            string         `yaml:"url"`
	RequestOptions struct {
		Headers map[string]any `yaml:"headers"`
	} `yaml:"requestOptions"`
}

type continueConfig struct {
	MCPServers []continueMCPServer `yaml:"mcpServers"`
}

// NewContinueDiscoverer creates a Continue config discoverer. The Continue
// IDE extension is reported separately by the AI extension discoverer.
func NewContinueDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := resolveHomeDir(config)
	if err != nil {
		return nil, err
	}

	continueDir := filepath.Join(homeDir, ".continue")
	workspaceDir := filepath.Join(".continue", "mcpServers")

	return newMCPAppDiscoverer(config, mcpAppSpec{
		app:            continueApp,
		appDisplay:     continueAppDisplay,
		agentMarkers:   []string{continueDir},
		systemMCPPaths: []string{filepath.Join(continueDir, "config.yaml")},
		// Workspace MCP servers are one YAML block file per server.
		projectMCPGlobs: []string{
			filepath.Join(workspaceDir, "*.yaml"),
			filepath.Join(workspaceDir, "*.yml"),
		},
		parse: parseContinueConfig,
	}), nil
}

func parseContinueConfig(path string) (*mcpAppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg continueConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse Continue config file %s: %v", path, err)
		return nil, err
	}

	servers := make(map[string]mcpServerEntry, len(cfg.MCPServers))
	for _, srv := range cfg.MCPServers {
		if srv.Name == "" {
			continue
		}
		servers[srv.Name] = mcpServerEntry{
			Type:    srv.Type,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
			URL:     srv.URL,
			Headers: srv.RequestOptions.Headers,
		}
	}

	return &mcpAppConfig{MCPServers: servers}, nil
}

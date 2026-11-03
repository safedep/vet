package aitool

import (
	"os"
	"path/filepath"

	"github.com/safedep/dry/log"
	"gopkg.in/yaml.v3"
)

const (
	continueApp        = "continue"
	continueAppDisplay = "Continue"
)

// continueMCPServer is one item of the "mcpServers" list in the YAML config
// of Continue. The servers are a list with a "name" key, not a map.
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

// NewContinueDiscoverer creates a Continue config discoverer. The AI
// extension discoverer reports the Continue IDE extension.
func NewContinueDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir, err := homeDirOf(config)
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
		// Each workspace MCP server has its own YAML block file.
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
		log.Warnf("Failed to parse Continue config file %s: %v", path, err)
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

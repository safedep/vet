package aitool

import (
	"os"
	"path/filepath"
)

const windsurfHost = "windsurf"

type windsurfDiscoverer struct {
	homeDir string
}

// NewWindsurfDiscoverer creates a Windsurf config discoverer.
func NewWindsurfDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &windsurfDiscoverer{homeDir: homeDir}, nil
}

func (d *windsurfDiscoverer) Name() string { return "Windsurf Config" }
func (d *windsurfDiscoverer) Host() string { return windsurfHost }

func (d *windsurfDiscoverer) EnumTools(handler AIToolHandlerFn) error {
	windsurfDir := filepath.Join(d.homeDir, ".codeium", "windsurf")
	mcpConfigPath := filepath.Join(windsurfDir, "mcp_config.json")

	// System-level: ~/.codeium/windsurf/mcp_config.json
	if cfg, err := parseMCPHostConfig(mcpConfigPath); err == nil {
		if err := emitMCPServers(cfg, mcpConfigPath, AIToolScopeSystem, windsurfHost, handler); err != nil {
			return err
		}
	}

	// Emit coding_agent if the windsurf config directory exists
	if info, err := os.Stat(windsurfDir); err == nil && info.IsDir() {
		agent := &AITool{
			Name:       "Windsurf",
			Type:       AIToolTypeCodingAgent,
			Scope:      AIToolScopeSystem,
			Host:       windsurfHost,
			ConfigPath: windsurfDir,
			Agent:      &AgentConfig{},
		}
		agent.ID = GenerateID(agent.Host, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
		agent.SourceID = GenerateSourceID(agent.Host, agent.ConfigPath)

		if err := handler(agent); err != nil {
			return err
		}
	}

	return nil
}

package aitool

import (
	"os"
	"path/filepath"
)

const windsurfApp = "windsurf"

type windsurfDiscoverer struct {
	homeDir string
	config  DiscoveryConfig
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
	return &windsurfDiscoverer{homeDir: homeDir, config: config}, nil
}

func (d *windsurfDiscoverer) Name() string { return "Windsurf Config" }
func (d *windsurfDiscoverer) App() string { return windsurfApp }

func (d *windsurfDiscoverer) EnumTools(handler AIToolHandlerFn) error {
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}

	windsurfDir := filepath.Join(d.homeDir, ".codeium", "windsurf")
	mcpConfigPath := filepath.Join(windsurfDir, "mcp_config.json")

	// System-level: ~/.codeium/windsurf/mcp_config.json
	if cfg, err := parseMCPAppConfig(mcpConfigPath); err == nil {
		if err := emitMCPServers(cfg, mcpConfigPath, AIToolScopeSystem, windsurfApp, handler); err != nil {
			return err
		}
	}

	// Emit coding_agent if the windsurf config directory exists
	if info, err := os.Stat(windsurfDir); err == nil && info.IsDir() {
		agent := &AITool{
			Name:       "Windsurf",
			Type:       AIToolTypeCodingAgent,
			Scope:      AIToolScopeSystem,
			App:       windsurfApp,
			ConfigPath: windsurfDir,
			Agent:      &AgentConfig{},
		}
		agent.ID = GenerateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
		agent.SourceID = GenerateSourceID(agent.App, agent.ConfigPath)

		if err := handler(agent); err != nil {
			return err
		}
	}

	return nil
}

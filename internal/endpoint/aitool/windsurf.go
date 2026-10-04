package aitool

import (
	"context"
	"os"
	"path/filepath"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

const (
	windsurfApp        = "windsurf"
	windsurfAppDisplay = "Windsurf"
)

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
func (d *windsurfDiscoverer) App() string  { return windsurfApp }

func (d *windsurfDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if !d.config.ScopeEnabled(inventory.ScopeSystem) {
		return nil
	}

	windsurfDir := filepath.Join(d.homeDir, ".codeium", "windsurf")
	mcpConfigPath := filepath.Join(windsurfDir, "mcp_config.json")

	// System-level: ~/.codeium/windsurf/mcp_config.json
	if cfg, err := parseMCPAppConfig(mcpConfigPath); err == nil {
		if err := emitMCPServers(cfg, mcpConfigPath, inventory.ScopeSystem, windsurfApp, windsurfAppDisplay, handler); err != nil {
			return err
		}
	}

	// Emit coding_agent if the windsurf config directory exists
	if info, err := os.Stat(windsurfDir); err == nil && info.IsDir() {
		agent := newItem(inventory.KindCodingAgent, inventory.ScopeSystem, windsurfApp, windsurfAppDisplay, "Windsurf", windsurfDir)
		agent.Agent = &inventory.AgentDetail{}

		if err := handler(agent); err != nil {
			return err
		}
	}

	return nil
}

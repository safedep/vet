package aitool

import (
	"context"
	"os"
	"path/filepath"
)

const (
	antigravityApp        = "antigravity"
	antigravityAppDisplay = "Antigravity"
)

type antigravityDiscoverer struct {
	homeDir string
	config  DiscoveryConfig
}

// NewAntigravityDiscoverer creates an Antigravity config discoverer.
func NewAntigravityDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &antigravityDiscoverer{
		homeDir: homeDir,
		config:  config,
	}, nil
}

func (d *antigravityDiscoverer) Name() string { return "Antigravity Config" }
func (d *antigravityDiscoverer) App() string  { return antigravityApp }

func (d *antigravityDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}

	// ~/.gemini/antigravity/mcp_config.json holds global MCP server config.
	systemMCPPath := filepath.Join(d.homeDir, ".gemini", "antigravity", "mcp_config.json")
	if cfg, err := parseMCPAppConfig(systemMCPPath); err == nil {
		if err := emitMCPServers(cfg, systemMCPPath, AIToolScopeSystem, antigravityApp, antigravityAppDisplay, handler); err != nil {
			return err
		}
	}

	// Emit coding_agent for the first known Antigravity data directory found.
	// Linux/macOS: ~/.antigravity (legacy), ~/.config/Antigravity (XDG config),
	// ~/.local/share/antigravity (XDG data).
	// Windows: %APPDATA%\Antigravity, %LOCALAPPDATA%\Antigravity.
	// os.Getenv returns "" on platforms where the variable is absent, causing
	// filepath.Join to produce a relative path that os.Stat will not find — the
	// directory is simply skipped.
	agDirs := []string{
		filepath.Join(d.homeDir, ".antigravity"),
		filepath.Join(d.homeDir, ".config", "Antigravity"),
		filepath.Join(d.homeDir, ".local", "share", "antigravity"),
		filepath.Join(os.Getenv("APPDATA"), "Antigravity"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Antigravity"),
	}
	for _, dir := range agDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		agent := &AITool{
			Name:       "Antigravity",
			Type:       AIToolTypeCodingAgent,
			Scope:      AIToolScopeSystem,
			App:        antigravityApp,
			AppDisplay: antigravityAppDisplay,
			ConfigPath: dir,
			Agent:      &AgentConfig{},
		}
		agent.ID = generateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
		agent.SourceID = generateSourceID(agent.App, agent.ConfigPath)

		if err := handler(agent); err != nil {
			return err
		}
		break
	}

	return nil
}

package aitool

import (
	"context"
	"os"
	"path/filepath"
)

const (
	vscodeApp        = "vscode"
	vscodeAppDisplay = "VS Code"
)

type vscodeDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewVSCodeDiscoverer creates a VS Code config discoverer.
func NewVSCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &vscodeDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *vscodeDiscoverer) Name() string { return "VS Code Config" }
func (d *vscodeDiscoverer) App() string  { return vscodeApp }

func (d *vscodeDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		// VS Code user-data directory is platform-specific; try all known
		// locations and use the first mcp.json that parses successfully.
		// Linux:   ~/.config/Code/User/
		// macOS:   ~/Library/Application Support/Code/User/
		// Windows: %APPDATA%\Code\User\
		// os.Getenv returns "" on platforms where the variable is absent so
		// filepath.Join("", ...) produces a relative path that os.Stat misses.
		userDataDirs := []string{
			filepath.Join(d.homeDir, ".config", "Code", "User"),
			filepath.Join(d.homeDir, "Library", "Application Support", "Code", "User"),
			filepath.Join(os.Getenv("APPDATA"), "Code", "User"),
		}
		for _, dir := range userDataDirs {
			path := filepath.Join(dir, "mcp.json")
			cfg, err := parseMCPAppConfig(path)
			if err != nil {
				continue
			}
			if err := emitMCPServers(cfg, path, AIToolScopeSystem, vscodeApp, vscodeAppDisplay, handler); err != nil {
				return err
			}
			break
		}

		vscodeDir := filepath.Join(d.homeDir, ".vscode")
		if info, err := os.Stat(vscodeDir); err == nil && info.IsDir() {
			agent := &AITool{
				Name:       "VS Code",
				Type:       AIToolTypeCodingAgent,
				Scope:      AIToolScopeSystem,
				App:        vscodeApp,
				AppDisplay: vscodeAppDisplay,
				ConfigPath: vscodeDir,
				Agent:      &AgentConfig{},
			}
			agent.ID = generateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
			agent.SourceID = generateSourceID(agent.App, agent.ConfigPath)

			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(AIToolScopeProject) && d.projectDir != "" {
		vscodeDir := filepath.Join(d.projectDir, ".vscode")
		for _, name := range []string{"mcp.json", "mcpservers.json", "mcp_config.json"} {
			path := filepath.Join(vscodeDir, name)
			cfg, err := parseMCPAppConfig(path)
			if err != nil {
				continue
			}
			return emitMCPServers(cfg, path, AIToolScopeProject, vscodeApp, vscodeAppDisplay, handler)
		}
	}

	return nil
}

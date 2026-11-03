package aitool

import (
	"context"
	"os"
	"path/filepath"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
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
	if d.config.ScopeEnabled(inventory.ScopeSystem) {
		// The VS Code user data folder depends on the OS. The first mcp.json
		// that parses wins.
		for _, dir := range vscodeUserDataDirs(d.homeDir) {
			if dir == "" {
				continue
			}
			path := filepath.Join(dir, "mcp.json")
			cfg, err := parseMCPAppConfig(path)
			if err != nil {
				continue
			}
			if err := emitMCPServers(cfg, path, inventory.ScopeSystem, vscodeApp, vscodeAppDisplay, handler); err != nil {
				return err
			}
			break
		}

		vscodeDir := filepath.Join(d.homeDir, ".vscode")
		if info, err := os.Stat(vscodeDir); err == nil && info.IsDir() {
			agent := newCodingAgent(vscodeApp, vscodeAppDisplay, vscodeDir)
			markAppBundle(agent, vscodeInstallMarkers())

			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(inventory.ScopeProject) && d.projectDir != "" {
		vscodeDir := filepath.Join(d.projectDir, ".vscode")
		for _, name := range []string{"mcp.json", "mcpservers.json", "mcp_config.json"} {
			path := filepath.Join(vscodeDir, name)
			cfg, err := parseMCPAppConfig(path)
			if err != nil {
				continue
			}
			return emitMCPServers(cfg, path, inventory.ScopeProject, vscodeApp, vscodeAppDisplay, handler)
		}
	}

	return nil
}

// vscodeInstallMarkers returns the documented VS Code install locations: the
// macOS app bundle, the Windows user and system setup folders, and the Linux
// deb and rpm install folder.
func vscodeInstallMarkers() []string {
	return []string{
		unixPath("Applications", "Visual Studio Code.app"),
		envPath("LOCALAPPDATA", "Programs", "Microsoft VS Code"),
		envPath("ProgramFiles", "Microsoft VS Code"),
		unixPath("usr", "share", "code"),
	}
}

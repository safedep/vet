package aitool

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	zedApp        = "zed"
	zedAppDisplay = "Zed"
)

// zedContextServerCommand holds the executable and its arguments for a Zed MCP server.
type zedContextServerCommand struct {
	Path string         `json:"path"`
	Args []string       `json:"args,omitempty"`
	Env  map[string]any `json:"env,omitempty"`
}

// zedContextServerEntry is a single entry in Zed's context_servers settings block.
// Source is typically "custom" for user-defined servers.
type zedContextServerEntry struct {
	Source  string                   `json:"source,omitempty"`
	Command *zedContextServerCommand `json:"command,omitempty"`
}

// zedSettings represents the subset of Zed's settings.json that we care about.
type zedSettings struct {
	ContextServers map[string]zedContextServerEntry `json:"context_servers,omitempty"`
}

type zedDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewZedDiscoverer creates a Zed config discoverer.
// It reads ~/.config/zed/settings.json and looks for the context_servers block
// which is Zed's mechanism for configuring MCP servers.
func NewZedDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &zedDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *zedDiscoverer) Name() string { return "Zed Config" }
func (d *zedDiscoverer) App() string  { return zedApp }

func (d *zedDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		zedConfigDir := zedConfigDirectory(d.homeDir)
		settingsPath := filepath.Join(zedConfigDir, "settings.json")

		if settings, err := parseZedSettings(settingsPath); err == nil {
			if err := emitZedContextServers(settings, settingsPath, AIToolScopeSystem, handler); err != nil {
				return err
			}
		}

		// Emit coding_agent if the Zed config directory exists
		if info, err := os.Stat(zedConfigDir); err == nil && info.IsDir() {
			agent := &AITool{
				Name:       zedAppDisplay,
				Type:       AIToolTypeCodingAgent,
				Scope:      AIToolScopeSystem,
				App:        zedApp,
				AppDisplay: zedAppDisplay,
				ConfigPath: zedConfigDir,
				Agent:      &AgentConfig{},
			}
			agent.ID = generateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
			agent.SourceID = generateSourceID(agent.App, agent.ConfigPath)

			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	return nil
}

// zedConfigDirectory returns the platform-appropriate Zed config directory.
// On macOS it is ~/Library/Application Support/Zed; on all other platforms
// it follows the XDG convention: ~/.config/zed.
func zedConfigDirectory(homeDir string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(homeDir, "Library", "Application Support", "Zed")
	}
	return filepath.Join(homeDir, ".config", "zed")
}

// parseZedSettings reads and unmarshals Zed's settings.json file.
func parseZedSettings(path string) (*zedSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var settings zedSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		logger.Warnf("Failed to parse Zed settings %s: %v", path, err)
		return nil, err
	}

	return &settings, nil
}

// emitZedContextServers converts Zed's context_servers entries into AITool MCP server entries.
// Zed uses a different JSON schema from the standard mcpServers format:
//
//	"context_servers": {
//	  "my-server": {
//	    "source": "custom",
//	    "command": { "path": "npx", "args": [...], "env": {...} }
//	  }
//	}
func emitZedContextServers(settings *zedSettings, configPath string, scope AIToolScope, handler AIToolHandlerFn) error {
	names := make([]string, 0, len(settings.ContextServers))
	for name := range settings.ContextServers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry := settings.ContextServers[name]

		mcpCfg := &MCPServerConfig{
			Transport: MCPTransportStdio,
		}

		if entry.Command != nil {
			mcpCfg.Command = entry.Command.Path
			mcpCfg.Args = SanitizeArgs(entry.Command.Args)
			mcpCfg.EnvVarNames = sortedMapKeys(entry.Command.Env)
		}

		tool := &AITool{
			Name:       name,
			Type:       AIToolTypeMCPServer,
			Scope:      scope,
			App:        zedApp,
			AppDisplay: zedAppDisplay,
			ConfigPath: configPath,
			MCPServer:  mcpCfg,
		}

		tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
		tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)

		if err := handler(tool); err != nil {
			return err
		}
	}

	return nil
}

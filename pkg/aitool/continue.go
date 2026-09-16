package aitool

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	continueApp        = "continue"
	continueAppDisplay = "Continue"
)

// continueServerEntry is a single MCP server in Continue's config.json.
// Continue uses an array of servers rather than the map-keyed format used by
// Claude Code / Cursor / Windsurf.
type continueServerEntry struct {
	Name      string         `json:"name"`
	Command   string         `json:"command,omitempty"`
	Args      []string       `json:"args,omitempty"`
	Env       map[string]any `json:"env,omitempty"`
	Transport string         `json:"transport,omitempty"`
	URL       string         `json:"url,omitempty"`
}

// continueConfig represents the relevant subset of Continue's config.json.
type continueConfig struct {
	MCPServers []continueServerEntry `json:"mcpServers,omitempty"`
}

type continueDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewContinueDiscoverer creates a Continue config discoverer.
// Continue (https://www.continue.dev) is an open-source AI coding assistant
// available as a VS Code / JetBrains extension.  Its system-level config lives
// at ~/.continue/config.json and supports MCP servers via an array of entries.
func NewContinueDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &continueDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *continueDiscoverer) Name() string { return "Continue Config" }
func (d *continueDiscoverer) App() string  { return continueApp }

func (d *continueDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		continueDir := filepath.Join(d.homeDir, ".continue")
		configPath := filepath.Join(continueDir, "config.json")

		if cfg, err := parseContinueConfig(configPath); err == nil {
			if err := emitContinueMCPServers(cfg, configPath, AIToolScopeSystem, handler); err != nil {
				return err
			}
		}

		// Emit coding_agent if the ~/.continue/ directory exists
		if info, err := os.Stat(continueDir); err == nil && info.IsDir() {
			agent := &AITool{
				Name:       continueAppDisplay,
				Type:       AIToolTypeCodingAgent,
				Scope:      AIToolScopeSystem,
				App:        continueApp,
				AppDisplay: continueAppDisplay,
				ConfigPath: continueDir,
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
		// Project-level: .continue/config.json
		projectConfigPath := filepath.Join(d.projectDir, ".continue", "config.json")
		if cfg, err := parseContinueConfig(projectConfigPath); err == nil {
			if err := emitContinueMCPServers(cfg, projectConfigPath, AIToolScopeProject, handler); err != nil {
				return err
			}
		}
	}

	return nil
}

// parseContinueConfig reads and parses Continue's config.json file.
func parseContinueConfig(path string) (*continueConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg continueConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse Continue config %s: %v", path, err)
		return nil, err
	}

	return &cfg, nil
}

// emitContinueMCPServers converts Continue's array-format mcpServers into AITool entries.
func emitContinueMCPServers(cfg *continueConfig, configPath string, scope AIToolScope, handler AIToolHandlerFn) error {
	for _, entry := range cfg.MCPServers {
		name := entry.Name
		if name == "" {
			continue
		}

		transport := continueMCPTransport(entry)

		mcpCfg := &MCPServerConfig{
			Transport:   transport,
			Command:     entry.Command,
			Args:        SanitizeArgs(entry.Args),
			URL:         entry.URL,
			EnvVarNames: sortedMapKeys(entry.Env),
		}

		tool := &AITool{
			Name:       name,
			Type:       AIToolTypeMCPServer,
			Scope:      scope,
			App:        continueApp,
			AppDisplay: continueAppDisplay,
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

// continueMCPTransport resolves the MCPTransport for a Continue server entry.
func continueMCPTransport(entry continueServerEntry) MCPTransport {
	switch entry.Transport {
	case "sse":
		return MCPTransportSSE
	case "streamable_http", "http":
		return MCPTransportStreamableHTTP
	case "stdio":
		return MCPTransportStdio
	}

	// Fall back to heuristics
	if entry.Command != "" {
		return MCPTransportStdio
	}
	if entry.URL != "" {
		return MCPTransportStreamableHTTP
	}
	return MCPTransportStdio
}

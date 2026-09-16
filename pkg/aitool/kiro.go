package aitool

import (
	"context"
	"os"
	"path/filepath"
)

const (
	kiroApp        = "kiro"
	kiroAppDisplay = "Kiro"
)

type kiroDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewKiroDiscoverer creates a Kiro config discoverer.
// Kiro is AWS's AI-powered IDE (https://kiro.dev).
// It stores MCP server configuration in ~/.kiro/settings/mcp.json using the
// standard mcpServers format shared with Claude Code / Cursor / Windsurf.
func NewKiroDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &kiroDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *kiroDiscoverer) Name() string { return "Kiro Config" }
func (d *kiroDiscoverer) App() string  { return kiroApp }

func (d *kiroDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		kiroDir := filepath.Join(d.homeDir, ".kiro")
		mcpConfigPath := filepath.Join(kiroDir, "settings", "mcp.json")

		// System-level: ~/.kiro/settings/mcp.json
		if cfg, err := parseMCPAppConfig(mcpConfigPath); err == nil {
			if err := emitMCPServers(cfg, mcpConfigPath, AIToolScopeSystem, kiroApp, kiroAppDisplay, handler); err != nil {
				return err
			}
		}

		// Emit coding_agent if the ~/.kiro/ directory exists
		if info, err := os.Stat(kiroDir); err == nil && info.IsDir() {
			agent := &AITool{
				Name:       kiroAppDisplay,
				Type:       AIToolTypeCodingAgent,
				Scope:      AIToolScopeSystem,
				App:        kiroApp,
				AppDisplay: kiroAppDisplay,
				ConfigPath: kiroDir,
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
		// Project-level: .kiro/settings/mcp.json
		projectMCPPath := filepath.Join(d.projectDir, ".kiro", "settings", "mcp.json")
		if cfg, err := parseMCPAppConfig(projectMCPPath); err == nil {
			if err := emitMCPServers(cfg, projectMCPPath, AIToolScopeProject, kiroApp, kiroAppDisplay, handler); err != nil {
				return err
			}
		}

		// Project-level steering files: .kiro/steering/*.md
		var instructionFiles []string
		steeringDir := filepath.Join(d.projectDir, ".kiro", "steering")
		entries, err := os.ReadDir(steeringDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					instructionFiles = append(instructionFiles, filepath.Join(steeringDir, entry.Name()))
				}
			}
		}

		if len(instructionFiles) > 0 {
			tool := &AITool{
				Name:       kiroAppDisplay,
				Type:       AIToolTypeProjectConfig,
				Scope:      AIToolScopeProject,
				App:        kiroApp,
				AppDisplay: kiroAppDisplay,
				ConfigPath: d.projectDir,
				Agent: &AgentConfig{
					InstructionFiles: instructionFiles,
				},
			}
			tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
			tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)

			if err := handler(tool); err != nil {
				return err
			}
		}
	}

	return nil
}

package aitool

import (
	"context"
	"os"
	"path/filepath"
)

const cursorApp = "cursor"

type cursorDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewCursorDiscoverer creates a Cursor config discoverer.
func NewCursorDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &cursorDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *cursorDiscoverer) Name() string { return "Cursor Config" }
func (d *cursorDiscoverer) App() string  { return cursorApp }

func (d *cursorDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		cursorDir := filepath.Join(d.homeDir, ".cursor")
		systemMCPPath := filepath.Join(cursorDir, "mcp.json")

		// System-level: ~/.cursor/mcp.json
		if cfg, err := parseMCPAppConfig(systemMCPPath); err == nil {
			if err := emitMCPServers(cfg, systemMCPPath, AIToolScopeSystem, cursorApp, handler); err != nil {
				return err
			}
		}

		// Emit coding_agent for Cursor if the ~/.cursor/ directory exists
		if info, err := os.Stat(cursorDir); err == nil && info.IsDir() {
			agent := &AITool{
				Name:       "Cursor",
				Type:       AIToolTypeCodingAgent,
				Scope:      AIToolScopeSystem,
				App:        cursorApp,
				ConfigPath: cursorDir,
				Agent:      &AgentConfig{},
			}
			agent.ID = GenerateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
			agent.SourceID = GenerateSourceID(agent.App, agent.ConfigPath)

			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(AIToolScopeProject) && d.projectDir != "" {
		if err := d.processProjectConfigs(handler); err != nil {
			return err
		}
	}

	return nil
}

func (d *cursorDiscoverer) processProjectConfigs(handler AIToolHandlerFn) error {
	// .cursor/mcp.json (project-scoped)
	projectMCPPath := filepath.Join(d.projectDir, ".cursor", "mcp.json")
	if cfg, err := parseMCPAppConfig(projectMCPPath); err == nil {
		if err := emitMCPServers(cfg, projectMCPPath, AIToolScopeProject, cursorApp, handler); err != nil {
			return err
		}
	}

	// Collect instruction files
	var instructionFiles []string

	// .cursorrules
	cursorRulesPath := filepath.Join(d.projectDir, ".cursorrules")
	if _, err := os.Stat(cursorRulesPath); err == nil {
		instructionFiles = append(instructionFiles, cursorRulesPath)
	}

	// .cursor/rules/*
	rulesDir := filepath.Join(d.projectDir, ".cursor", "rules")
	entries, err := os.ReadDir(rulesDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				instructionFiles = append(instructionFiles, filepath.Join(rulesDir, entry.Name()))
			}
		}
	}

	if len(instructionFiles) > 0 {
		tool := &AITool{
			Name:       "Cursor",
			Type:       AIToolTypeProjectConfig,
			Scope:      AIToolScopeProject,
			App:        cursorApp,
			ConfigPath: d.projectDir,
			Agent: &AgentConfig{
				InstructionFiles: instructionFiles,
			},
		}
		tool.ID = GenerateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
		tool.SourceID = GenerateSourceID(tool.App, tool.ConfigPath)

		if err := handler(tool); err != nil {
			return err
		}
	}

	return nil
}

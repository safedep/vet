package aitool

import (
	"os"
	"path/filepath"
)

const cursorHost = "cursor"

type cursorDiscoverer struct {
	homeDir    string
	projectDir string
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
	}, nil
}

func (d *cursorDiscoverer) Name() string { return "Cursor Config" }
func (d *cursorDiscoverer) Host() string { return cursorHost }

func (d *cursorDiscoverer) EnumTools(handler AIToolHandlerFn) error {
	cursorDir := filepath.Join(d.homeDir, ".cursor")
	systemMCPPath := filepath.Join(cursorDir, "mcp.json")

	// System-level: ~/.cursor/mcp.json
	if cfg, err := parseMCPHostConfig(systemMCPPath); err == nil {
		if err := emitMCPServers(cfg, systemMCPPath, AIToolScopeSystem, cursorHost, handler); err != nil {
			return err
		}
	}

	// Emit coding_agent for Cursor if the ~/.cursor/ directory exists,
	// regardless of whether mcp.json is present.
	if info, err := os.Stat(cursorDir); err == nil && info.IsDir() {
		agent := &AITool{
			Name:       "Cursor",
			Type:       AIToolTypeCodingAgent,
			Scope:      AIToolScopeSystem,
			Host:       cursorHost,
			ConfigPath: cursorDir,
			Agent:      &AgentConfig{},
		}
		agent.ID = GenerateID(agent.Host, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
		agent.SourceID = GenerateSourceID(agent.Host, agent.ConfigPath)

		if err := handler(agent); err != nil {
			return err
		}
	}

	// Project-level configs
	if d.projectDir != "" {
		if err := d.processProjectConfigs(handler); err != nil {
			return err
		}
	}

	return nil
}

func (d *cursorDiscoverer) processProjectConfigs(handler AIToolHandlerFn) error {
	// .cursor/mcp.json (project-scoped)
	projectMCPPath := filepath.Join(d.projectDir, ".cursor", "mcp.json")
	if cfg, err := parseMCPHostConfig(projectMCPPath); err == nil {
		if err := emitMCPServers(cfg, projectMCPPath, AIToolScopeProject, cursorHost, handler); err != nil {
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
			Host:       cursorHost,
			ConfigPath: d.projectDir,
			Agent: &AgentConfig{
				InstructionFiles: instructionFiles,
			},
		}
		tool.ID = GenerateID(tool.Host, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
		tool.SourceID = GenerateSourceID(tool.Host, tool.ConfigPath)

		if err := handler(tool); err != nil {
			return err
		}
	}

	return nil
}

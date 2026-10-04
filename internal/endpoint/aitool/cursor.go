package aitool

import (
	"context"
	"os"
	"path/filepath"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

const (
	cursorApp        = "cursor"
	cursorAppDisplay = "Cursor"
)

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
	if d.config.ScopeEnabled(inventory.ScopeSystem) {
		cursorDir := filepath.Join(d.homeDir, ".cursor")
		systemMCPPath := filepath.Join(cursorDir, "mcp.json")

		// System-level: ~/.cursor/mcp.json
		if cfg, err := parseMCPAppConfig(systemMCPPath); err == nil {
			if err := emitMCPServers(cfg, systemMCPPath, inventory.ScopeSystem, cursorApp, cursorAppDisplay, handler); err != nil {
				return err
			}
		}

		// Emit coding_agent for Cursor if the ~/.cursor/ directory exists
		if info, err := os.Stat(cursorDir); err == nil && info.IsDir() {
			agent := newItem(inventory.KindCodingAgent, inventory.ScopeSystem, cursorApp, cursorAppDisplay, "Cursor", cursorDir)
			agent.Agent = &inventory.AgentDetail{}

			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(inventory.ScopeProject) && d.projectDir != "" {
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
		if err := emitMCPServers(cfg, projectMCPPath, inventory.ScopeProject, cursorApp, cursorAppDisplay, handler); err != nil {
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
		item := newItem(inventory.KindProjectConfig, inventory.ScopeProject, cursorApp, cursorAppDisplay, "Cursor", d.projectDir)
		item.Agent = &inventory.AgentDetail{InstructionFiles: instructionFiles}

		if err := handler(item); err != nil {
			return err
		}
	}

	return nil
}

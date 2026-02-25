package aitool

import (
	"context"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	claudeCodeApp        = "claude_code"
	claudeCodeAppDisplay = "Claude Code"
)

type claudeCodeDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewClaudeCodeDiscoverer creates a Claude Code config discoverer.
func NewClaudeCodeDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}

	return &claudeCodeDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *claudeCodeDiscoverer) Name() string { return "Claude Code Config" }
func (d *claudeCodeDiscoverer) App() string  { return claudeCodeApp }

func (d *claudeCodeDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		// System-level: ~/.claude/settings.json
		systemSettingsPath := filepath.Join(d.homeDir, ".claude", "settings.json")
		if err := d.processSystemSettings(systemSettingsPath, handler); err != nil {
			return err
		}

		// System-level: walk ~/.claude/projects/*/settings.json
		if err := d.walkProjectSettings(handler); err != nil {
			return err
		}
	}

	if d.config.ScopeEnabled(AIToolScopeProject) && d.projectDir != "" {
		if err := d.processProjectConfigs(handler); err != nil {
			return err
		}
	}

	return nil
}

func (d *claudeCodeDiscoverer) processSystemSettings(path string, handler AIToolHandlerFn) error {
	cfg, err := parseMCPAppConfig(path)
	if err != nil {
		logger.Debugf("Claude Code system settings not found or unreadable: %s", path)
		return nil
	}

	// Emit coding_agent for Claude Code itself
	agent := &AITool{
		Name:       "Claude Code",
		Type:       AIToolTypeCodingAgent,
		Scope:      AIToolScopeSystem,
		App:        claudeCodeApp,
		AppDisplay: claudeCodeAppDisplay,
		ConfigPath: path,
		Agent:      &AgentConfig{},
	}

	if cfg.Model != "" {
		agent.Agent.Model = cfg.Model
	}

	if mode := claudeCodePermissionMode(cfg); mode != "" {
		agent.Agent.PermissionMode = mode
	}

	agent.ID = generateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
	agent.SourceID = generateSourceID(agent.App, agent.ConfigPath)

	if err := handler(agent); err != nil {
		return err
	}

	// Emit MCP servers from system settings
	return emitMCPServers(cfg, path, AIToolScopeSystem, claudeCodeApp, claudeCodeAppDisplay, handler)
}

func (d *claudeCodeDiscoverer) walkProjectSettings(handler AIToolHandlerFn) error {
	projectsDir := filepath.Join(d.homeDir, ".claude", "projects")
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		logger.Debugf("Claude Code projects directory not found: %s", projectsDir)
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		settingsPath := filepath.Join(projectsDir, entry.Name(), "settings.json")
		cfg, err := parseMCPAppConfig(settingsPath)
		if err != nil {
			continue
		}

		if err := emitMCPServers(cfg, settingsPath, AIToolScopeSystem, claudeCodeApp, claudeCodeAppDisplay, handler); err != nil {
			return err
		}
	}

	return nil
}

func (d *claudeCodeDiscoverer) processProjectConfigs(handler AIToolHandlerFn) error {
	// .mcp.json
	mcpJSONPath := filepath.Join(d.projectDir, ".mcp.json")
	if cfg, err := parseMCPAppConfig(mcpJSONPath); err == nil {
		if err := emitMCPServers(cfg, mcpJSONPath, AIToolScopeProject, claudeCodeApp, claudeCodeAppDisplay, handler); err != nil {
			return err
		}
	}

	// .claude/settings.json (project-scoped)
	projectSettingsPath := filepath.Join(d.projectDir, ".claude", "settings.json")
	if cfg, err := parseMCPAppConfig(projectSettingsPath); err == nil {
		if err := emitMCPServers(cfg, projectSettingsPath, AIToolScopeProject, claudeCodeApp, claudeCodeAppDisplay, handler); err != nil {
			return err
		}
	}

	// Check for CLAUDE.md instruction file
	var instructionFiles []string
	claudeMDPath := filepath.Join(d.projectDir, "CLAUDE.md")
	if _, err := os.Stat(claudeMDPath); err == nil {
		instructionFiles = append(instructionFiles, claudeMDPath)
	}

	if len(instructionFiles) > 0 {
		tool := &AITool{
			Name:       "Claude Code",
			Type:       AIToolTypeProjectConfig,
			Scope:      AIToolScopeProject,
			App:        claudeCodeApp,
			AppDisplay: claudeCodeAppDisplay,
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

	return nil
}

// claudeCodePermissionMode extracts the permission mode string from a parsed config.
// Claude Code stores this as {"permissions": {"defaultMode": "..."}}.
func claudeCodePermissionMode(cfg *mcpAppConfig) string {
	if cfg.Permissions == nil {
		return ""
	}

	if mode, ok := cfg.Permissions["defaultMode"].(string); ok {
		return mode
	}

	return ""
}

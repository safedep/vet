package aitool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
)

const claudeCodeHost = "claude_code"

// claudeCodeMCPServerEntry represents a single MCP server in a Claude Code config file.
// Cursor shares the same JSON shape, so this struct is reused by the Cursor discoverer.
type claudeCodeMCPServerEntry struct {
	Command      string         `json:"command,omitempty"`
	Args         []string       `json:"args,omitempty"`
	URL          string         `json:"url,omitempty"`
	Type         string         `json:"type,omitempty"`
	Env          map[string]any `json:"env,omitempty"`
	Headers      map[string]any `json:"headers,omitempty"`
	Disabled     *bool          `json:"disabled,omitempty"`
	AllowedTools []string       `json:"allowedTools,omitempty"`
}

// claudeCodeConfig represents a Claude Code settings.json file. The Permissions
// and Model fields are Claude Code specific. Cursor reuses this struct because
// its mcp.json shares the mcpServers key.
type claudeCodeConfig struct {
	MCPServers  map[string]claudeCodeMCPServerEntry `json:"mcpServers,omitempty"`
	Permissions map[string]any                      `json:"permissions,omitempty"`
	Model       string                              `json:"model,omitempty"`
}

type claudeCodeDiscoverer struct {
	homeDir    string
	projectDir string
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
	}, nil
}

func (d *claudeCodeDiscoverer) Name() string { return "Claude Code Config" }
func (d *claudeCodeDiscoverer) Host() string { return claudeCodeHost }

func (d *claudeCodeDiscoverer) EnumTools(handler AIToolHandlerFn) error {
	// System-level: ~/.claude/settings.json
	systemSettingsPath := filepath.Join(d.homeDir, ".claude", "settings.json")
	if err := d.processSystemSettings(systemSettingsPath, handler); err != nil {
		return err
	}

	// System-level: walk ~/.claude/projects/*/settings.json
	if err := d.walkProjectSettings(handler); err != nil {
		return err
	}

	// Project-level configs
	if d.projectDir != "" {
		if err := d.processProjectConfigs(handler); err != nil {
			return err
		}
	}

	return nil
}

func (d *claudeCodeDiscoverer) processSystemSettings(path string, handler AIToolHandlerFn) error {
	cfg, err := parseClaudeCodeConfig(path)
	if err != nil {
		logger.Debugf("Claude Code system settings not found or unreadable: %s", path)
		return nil
	}

	// Emit coding_agent for Claude Code itself
	agent := &AITool{
		Name:       "Claude Code",
		Type:       AIToolTypeCodingAgent,
		Scope:      AIToolScopeSystem,
		Host:       claudeCodeHost,
		ConfigPath: path,
		Agent:      &AgentConfig{},
	}

	if cfg.Model != "" {
		agent.Agent.Model = cfg.Model
	}

	if mode := permissionMode(cfg); mode != "" {
		agent.Agent.PermissionMode = mode
	}

	agent.ID = GenerateID(agent.Host, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
	agent.SourceID = GenerateSourceID(agent.Host, agent.ConfigPath)

	if err := handler(agent); err != nil {
		return err
	}

	// Emit MCP servers from system settings
	return emitMCPServers(cfg, path, AIToolScopeSystem, claudeCodeHost, handler)
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
		cfg, err := parseClaudeCodeConfig(settingsPath)
		if err != nil {
			continue
		}

		if err := emitMCPServers(cfg, settingsPath, AIToolScopeProject, claudeCodeHost, handler); err != nil {
			return err
		}
	}

	return nil
}

func (d *claudeCodeDiscoverer) processProjectConfigs(handler AIToolHandlerFn) error {
	// .mcp.json
	mcpJSONPath := filepath.Join(d.projectDir, ".mcp.json")
	if cfg, err := parseClaudeCodeConfig(mcpJSONPath); err == nil {
		if err := emitMCPServers(cfg, mcpJSONPath, AIToolScopeProject, claudeCodeHost, handler); err != nil {
			return err
		}
	}

	// .claude/settings.json (project-scoped)
	projectSettingsPath := filepath.Join(d.projectDir, ".claude", "settings.json")
	if cfg, err := parseClaudeCodeConfig(projectSettingsPath); err == nil {
		if err := emitMCPServers(cfg, projectSettingsPath, AIToolScopeProject, claudeCodeHost, handler); err != nil {
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
			Host:       claudeCodeHost,
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

// permissionMode extracts the permission mode string from a parsed config.
// Claude Code stores this as {"permissions": {"defaultMode": "..."}}.
func permissionMode(cfg *claudeCodeConfig) string {
	if cfg.Permissions == nil {
		return ""
	}

	if mode, ok := cfg.Permissions["defaultMode"].(string); ok {
		return mode
	}

	return ""
}

// parseClaudeCodeConfig reads and parses a JSON config file that may contain mcpServers.
func parseClaudeCodeConfig(path string) (*claudeCodeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg claudeCodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse config file %s: %v", path, err)
		return nil, err
	}

	return &cfg, nil
}

// detectTransport determines the MCP transport from a server entry.
// An explicit "type" field takes priority over heuristics.
func detectTransport(entry claudeCodeMCPServerEntry) MCPTransport {
	// Explicit type declaration takes precedence
	switch strings.ReplaceAll(strings.ToLower(entry.Type), "-", "_") {
	case "sse":
		return MCPTransportSSE
	case "streamable_http":
		return MCPTransportStreamableHTTP
	case "stdio":
		return MCPTransportStdio
	}

	// Fall back to heuristics from command/url presence
	if entry.Command != "" {
		return MCPTransportStdio
	}
	if entry.URL != "" {
		if strings.Contains(entry.URL, "/sse") {
			return MCPTransportSSE
		}
		return MCPTransportStreamableHTTP
	}
	return MCPTransportStdio
}

// emitMCPServers creates and emits AITool entries for all MCP servers in a config.
func emitMCPServers(cfg *claudeCodeConfig, configPath string, scope AIToolScope, host string, handler AIToolHandlerFn) error {
	for _, name := range sortedKeys(cfg.MCPServers) {
		entry := cfg.MCPServers[name]

		transport := detectTransport(entry)

		mcpCfg := &MCPServerConfig{
			Transport:    transport,
			Command:      entry.Command,
			Args:         SanitizeArgs(entry.Args),
			URL:          entry.URL,
			EnvVarNames:  sortedMapKeys(entry.Env),
			HeaderNames:  sortedMapKeys(entry.Headers),
			AllowedTools: entry.AllowedTools,
		}

		tool := &AITool{
			Name:       name,
			Type:       AIToolTypeMCPServer,
			Scope:      scope,
			Host:       host,
			ConfigPath: configPath,
			MCPServer:  mcpCfg,
		}

		if entry.Disabled != nil {
			enabled := !*entry.Disabled
			tool.Enabled = &enabled
		}

		tool.ID = GenerateID(tool.Host, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
		tool.SourceID = GenerateSourceID(tool.Host, tool.ConfigPath)

		if err := handler(tool); err != nil {
			return err
		}
	}
	return nil
}

// sortedKeys returns the keys of a map in sorted order for deterministic output.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedMapKeys returns the sorted keys of a map[string]any.
func sortedMapKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	return sortedKeys(m)
}

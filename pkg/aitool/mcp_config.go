package aitool

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
)

// mcpServerEntry represents a single MCP server entry in an app config file.
// This format is shared across Claude Code, Cursor, and Windsurf. Windsurf uses
// "serverUrl" instead of "url" for remote servers; resolvedURL() normalizes this.
type mcpServerEntry struct {
	Command      string         `json:"command,omitempty"`
	Args         []string       `json:"args,omitempty"`
	URL          string         `json:"url,omitempty"`
	ServerURL    string         `json:"serverUrl,omitempty"`
	Type         string         `json:"type,omitempty"`
	Env          map[string]any `json:"env,omitempty"`
	Headers      map[string]any `json:"headers,omitempty"`
	Disabled     *bool          `json:"disabled,omitempty"`
	AllowedTools []string       `json:"allowedTools,omitempty"`
}

// resolvedURL returns the effective URL, preferring URL over ServerURL.
func (e mcpServerEntry) resolvedURL() string {
	if e.URL != "" {
		return e.URL
	}
	return e.ServerURL
}

// mcpAppConfig represents an application's JSON config file containing
// MCP servers. The Permissions and Model fields are used by Claude Code;
// other apps ignore them during JSON unmarshaling.
type mcpAppConfig struct {
	MCPServers  map[string]mcpServerEntry `json:"mcpServers,omitempty"`
	Permissions map[string]any            `json:"permissions,omitempty"`
	Model       string                    `json:"model,omitempty"`
}

// parseMCPAppConfig reads and parses a JSON config file that contains mcpServers.
func parseMCPAppConfig(path string) (*mcpAppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg mcpAppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse config file %s: %v", path, err)
		return nil, err
	}

	return &cfg, nil
}

// detectTransport determines the MCP transport from a server entry.
// An explicit "type" field takes priority over heuristics.
func detectTransport(entry mcpServerEntry) MCPTransport {
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
	if u := entry.resolvedURL(); u != "" {
		if strings.Contains(u, "/sse") {
			return MCPTransportSSE
		}
		return MCPTransportStreamableHTTP
	}
	return MCPTransportStdio
}

// emitMCPServers creates and emits AITool entries for all MCP servers in a config.
func emitMCPServers(cfg *mcpAppConfig, configPath string, scope AIToolScope, app, appDisplay string, handler AIToolHandlerFn) error {
	for _, name := range sortedKeys(cfg.MCPServers) {
		entry := cfg.MCPServers[name]

		transport := detectTransport(entry)

		mcpCfg := &MCPServerConfig{
			Transport:    transport,
			Command:      entry.Command,
			Args:         SanitizeArgs(entry.Args),
			URL:          entry.resolvedURL(),
			EnvVarNames:  sortedMapKeys(entry.Env),
			HeaderNames:  sortedMapKeys(entry.Headers),
			AllowedTools: entry.AllowedTools,
		}

		tool := &AITool{
			Name:       name,
			Type:       AIToolTypeMCPServer,
			Scope:      scope,
			App:        app,
			AppDisplay: appDisplay,
			ConfigPath: configPath,
			MCPServer:  mcpCfg,
		}

		if entry.Disabled != nil {
			enabled := !*entry.Disabled
			tool.Enabled = &enabled
		}

		tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
		tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)

		if err := handler(tool); err != nil {
			return err
		}
	}
	return nil
}

// claudeProjectEntry represents one entry under the "projects" key in
// ~/.claude.json. Each key is an absolute project path.
type claudeProjectEntry struct {
	MCPServers         map[string]mcpServerEntry `json:"mcpServers"`
	DisabledMCPServers []string                  `json:"disabledMcpServers"`
}

// claudeUserConfigFile represents the structure of ~/.claude.json that is
// relevant for MCP discovery. The file contains many other fields; they are
// ignored during unmarshaling.
type claudeUserConfigFile struct {
	MCPServers map[string]mcpServerEntry        `json:"mcpServers"`
	Projects   map[string]claudeProjectEntry    `json:"projects"`
}

// parseClaudeUserConfigFile reads and parses ~/.claude.json into the fields
// relevant for MCP discovery.
func parseClaudeUserConfigFile(path string) (*claudeUserConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg claudeUserConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		logger.Warnf("Failed to parse Claude user config file %s: %v", path, err)
		return nil, err
	}
	return &cfg, nil
}

// projectEntryToMCPConfig converts a claudeProjectEntry into an mcpAppConfig,
// applying the per-project disabledMcpServers list by setting Disabled=true on
// each affected entry. This lets emitMCPServers set Enabled=false correctly.
func projectEntryToMCPConfig(entry claudeProjectEntry) *mcpAppConfig {
	disabled := make(map[string]bool, len(entry.DisabledMCPServers))
	for _, n := range entry.DisabledMCPServers {
		disabled[n] = true
	}
	servers := make(map[string]mcpServerEntry, len(entry.MCPServers))
	for name, srv := range entry.MCPServers {
		if disabled[name] {
			t := true
			srv.Disabled = &t
		}
		servers[name] = srv
	}
	return &mcpAppConfig{MCPServers: servers}
}

// parsePluginMCPConfig reads a plugin cache .mcp.json. It tries the standard
// mcpServers-wrapped format first; when that yields no servers it falls back
// to the bare map[name]entry format used by some plugins.
func parsePluginMCPConfig(path string) (*mcpAppConfig, error) {
	cfg, err := parseMCPAppConfig(path)
	if err != nil {
		return nil, err
	}
	if len(cfg.MCPServers) > 0 {
		return cfg, nil
	}
	return parseMCPBareConfig(path)
}

// parseMCPBareConfig reads a JSON file where server entries sit at the top
// level (no mcpServers wrapper). This format appears in Claude Code plugin
// cache .mcp.json files from some plugin publishers.
func parseMCPBareConfig(path string) (*mcpAppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries map[string]mcpServerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		logger.Warnf("Failed to parse bare MCP config file %s: %v", path, err)
		return nil, err
	}
	return &mcpAppConfig{MCPServers: entries}, nil
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

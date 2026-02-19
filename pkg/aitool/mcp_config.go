package aitool

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
)

// mcpServerEntry represents a single MCP server entry in a host config file.
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

// mcpHostConfig represents a host application's JSON config file containing
// MCP servers. The Permissions and Model fields are used by Claude Code;
// other hosts ignore them during JSON unmarshaling.
type mcpHostConfig struct {
	MCPServers  map[string]mcpServerEntry `json:"mcpServers,omitempty"`
	Permissions map[string]any            `json:"permissions,omitempty"`
	Model       string                    `json:"model,omitempty"`
}

// parseMCPHostConfig reads and parses a JSON config file that contains mcpServers.
func parseMCPHostConfig(path string) (*mcpHostConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg mcpHostConfig
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
func emitMCPServers(cfg *mcpHostConfig, configPath string, scope AIToolScope, host string, handler AIToolHandlerFn) error {
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

package aitool

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
)

// AIToolType classifies the kind of AI tool discovered.
type AIToolType string

const (
	AIToolTypeMCPServer     AIToolType = "mcp_server"
	AIToolTypeCodingAgent   AIToolType = "coding_agent"
	AIToolTypeAIExtension   AIToolType = "ai_extension"
	AIToolTypeCLITool       AIToolType = "cli_tool"
	AIToolTypeProjectConfig AIToolType = "project_config"
)

// AIToolScope distinguishes system-level (global) from project-level (repo-scoped) configs.
type AIToolScope string

const (
	AIToolScopeSystem  AIToolScope = "system"
	AIToolScopeProject AIToolScope = "project"
)

// MCPTransport identifies the transport protocol for an MCP server.
type MCPTransport string

const (
	MCPTransportStdio          MCPTransport = "stdio"
	MCPTransportSSE            MCPTransport = "sse"
	MCPTransportStreamableHTTP MCPTransport = "streamable_http"
)

// MCPServerConfig holds configuration details for a discovered MCP server.
type MCPServerConfig struct {
	Transport        MCPTransport `json:"transport"`
	Command          string       `json:"command,omitempty"`
	Args             []string     `json:"args,omitempty"`
	URL              string       `json:"url,omitempty"`
	EnvVarNames      []string     `json:"env_var_names,omitempty"`
	HeaderNames      []string     `json:"header_names,omitempty"`
	AllowedTools     []string     `json:"allowed_tools,omitempty"`
	AllowedResources []string     `json:"allowed_resources,omitempty"`
}

// AgentConfig holds configuration details for a discovered AI coding agent.
type AgentConfig struct {
	Version          string   `json:"version,omitempty"`
	PermissionMode   string   `json:"permission_mode,omitempty"`
	InstructionFiles []string `json:"instruction_files,omitempty"`
	Model            string   `json:"model,omitempty"`
	APIKeyEnvName    string   `json:"api_key_env_name,omitempty"`
}

// AITool represents a discovered AI tool, MCP server, or coding agent
// configured on the local system or within a project.
type AITool struct {
	ID         string      `json:"id"`
	SourceID   string      `json:"source_id"`
	Name       string      `json:"name"`
	Type       AIToolType  `json:"type"`
	Scope      AIToolScope `json:"scope"`
	App        string      `json:"app"`
	ConfigPath string      `json:"config_path"`

	MCPServer *MCPServerConfig `json:"mcp_server,omitempty"`
	Agent     *AgentConfig     `json:"agent,omitempty"`
	Enabled   *bool            `json:"enabled,omitempty"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}

// SetMeta sets a metadata key-value pair, initializing the map if needed.
func (t *AITool) SetMeta(key string, value any) {
	if t.Metadata == nil {
		t.Metadata = make(map[string]any)
	}
	t.Metadata[key] = value
}

// GetMeta retrieves a metadata value by key. Returns nil if not found.
func (t *AITool) GetMeta(key string) any {
	if t.Metadata == nil {
		return nil
	}
	return t.Metadata[key]
}

// GetMetaString retrieves a metadata value as a string. Returns "" if
// not found or not a string.
func (t *AITool) GetMetaString(key string) string {
	v, _ := t.GetMeta(key).(string)
	return v
}

// GenerateID produces a deterministic ID for an AITool from its identity fields.
func GenerateID(app, toolType, scope, name, configPath string) string {
	data := fmt.Sprintf("%s/%s/%s/%s/%s",
		strings.ToLower(app),
		strings.ToLower(toolType),
		strings.ToLower(scope),
		strings.ToLower(name),
		strings.ToLower(configPath))
	h := fnv.New64a()
	h.Write([]byte(data))
	return strconv.FormatUint(h.Sum64(), 16)
}

// GenerateSourceID produces a deterministic source grouping ID.
// Tools from the same app + config file share a SourceID.
func GenerateSourceID(app, configPath string) string {
	data := fmt.Sprintf("%s/%s",
		strings.ToLower(app),
		strings.ToLower(configPath))
	h := fnv.New64a()
	h.Write([]byte(data))
	return strconv.FormatUint(h.Sum64(), 16)
}

// AIToolInventory is a convenience wrapper for collecting all discovered tools.
type AIToolInventory struct {
	Tools []*AITool `json:"tools"`
}

// NewAIToolInventory creates a new empty inventory.
func NewAIToolInventory() *AIToolInventory {
	return &AIToolInventory{}
}

// Add appends a tool to the inventory.
func (inv *AIToolInventory) Add(tool *AITool) {
	inv.Tools = append(inv.Tools, tool)
}

// FilterByType returns tools matching the given type.
func (inv *AIToolInventory) FilterByType(t AIToolType) []*AITool {
	var result []*AITool
	for _, tool := range inv.Tools {
		if tool.Type == t {
			result = append(result, tool)
		}
	}
	return result
}

// FilterByApp returns tools matching the given app.
func (inv *AIToolInventory) FilterByApp(app string) []*AITool {
	var result []*AITool
	for _, tool := range inv.Tools {
		if tool.App == app {
			result = append(result, tool)
		}
	}
	return result
}

// FilterByScope returns tools matching the given scope.
func (inv *AIToolInventory) FilterByScope(scope AIToolScope) []*AITool {
	var result []*AITool
	for _, tool := range inv.Tools {
		if tool.Scope == scope {
			result = append(result, tool)
		}
	}
	return result
}

// FilterBySourceID returns tools matching the given source ID.
func (inv *AIToolInventory) FilterBySourceID(sourceID string) []*AITool {
	var result []*AITool
	for _, tool := range inv.Tools {
		if tool.SourceID == sourceID {
			result = append(result, tool)
		}
	}
	return result
}

// GroupByApp returns tools grouped by app name.
func (inv *AIToolInventory) GroupByApp() map[string][]*AITool {
	result := make(map[string][]*AITool)
	for _, tool := range inv.Tools {
		result[tool.App] = append(result[tool.App], tool)
	}
	return result
}

// GroupBySourceID returns tools grouped by source config.
func (inv *AIToolInventory) GroupBySourceID() map[string][]*AITool {
	result := make(map[string][]*AITool)
	for _, tool := range inv.Tools {
		result[tool.SourceID] = append(result[tool.SourceID], tool)
	}
	return result
}

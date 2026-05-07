// Package inventory defines the producer pipeline for endpoint inventory
// scans. The Item type is a domain-level mirror of the proto
// VetInventoryEvent.ItemObserved sub-message; proto translation lives
// outside this package (in CloudSink).
package inventory

// Kind classifies the subject of an ItemObserved event. Values mirror the
// proto InventoryItemKind enum.
type Kind int

const (
	// KindUnspecified is the zero value; not a valid kind.
	KindUnspecified Kind = 0
	// KindMCPServer is a discovered MCP server config entry.
	KindMCPServer Kind = 1
	// KindCodingAgent is a discovered AI coding agent.
	KindCodingAgent Kind = 2
	// KindAIExtension is a discovered AI editor / IDE extension.
	KindAIExtension Kind = 3
	// KindCLITool is a discovered CLI tool binary.
	KindCLITool Kind = 4
	// KindProjectConfig is a discovered project-level config file.
	KindProjectConfig Kind = 5
	// KindBrowserExtension is a discovered browser extension.
	KindBrowserExtension Kind = 6
	// KindIDEExtension is a discovered (non-AI) IDE extension.
	KindIDEExtension Kind = 7
	// KindAgentPlugin is a discovered coding-agent plugin.
	KindAgentPlugin Kind = 8
	// KindAgentSkill is a discovered coding-agent skill.
	KindAgentSkill Kind = 9
)

// Scope captures whether an item is system-wide or project-local. Values
// mirror the proto InventoryScope enum.
type Scope int

const (
	// ScopeUnspecified is the zero value; not a valid scope.
	ScopeUnspecified Scope = 0
	// ScopeSystem indicates a user / machine wide installation.
	ScopeSystem Scope = 1
	// ScopeProject indicates a project-local installation.
	ScopeProject Scope = 2
)

// Item is the in-process representation of a single discovered inventory
// item. Field-for-field equivalent to proto VetInventoryEvent.ItemObserved
// using Go-idiomatic naming. Pointer fields preserve the proto's
// optional semantics.
type Item struct {
	// Kind classifies the item.
	Kind Kind
	// ItemIdentity is the deterministic dedup key (FNV-64a of
	// app/kind/scope/name/config_path); computed by the scanner adapter.
	ItemIdentity string
	// SourceID groups items emitted from the same source (app + config file).
	SourceID string
	// Name is the human-readable label for the item.
	Name string
	// App is the application that owns / configures this item.
	App string
	// Scope is system-wide vs project-local.
	Scope Scope
	// ConfigPath is the absolute path to the config file the item was found in.
	ConfigPath string
	// Enabled is the optional enabled flag; nil means unknown.
	Enabled *bool
	// MCPServer carries MCP-server-specific details when Kind == KindMCPServer.
	MCPServer *MCPServerDetail
	// Agent carries coding-agent-specific details when Kind == KindCodingAgent.
	Agent *AgentDetail
	// Metadata holds free-form, kind-specific attributes for kinds without a
	// typed sub-message (CLI tools, AI extensions, etc.).
	Metadata map[string]string
}

// Transport classifies an MCP server's wire protocol. Mirrors the proto
// VetInventoryEvent.MCPServerDetail.Transport enum.
type Transport int

const (
	// TransportUnspecified is the zero value; not a valid transport.
	TransportUnspecified Transport = 0
	// TransportStdio uses standard input/output to a local process.
	TransportStdio Transport = 1
	// TransportSSE uses HTTP Server-Sent Events.
	TransportSSE Transport = 2
	// TransportStreamableHTTP uses the streamable-HTTP MCP transport.
	TransportStreamableHTTP Transport = 3
)

// MCPServerDetail mirrors proto VetInventoryEvent.MCPServerDetail. Populated
// only when Kind == KindMCPServer.
type MCPServerDetail struct {
	// Transport is the MCP transport classification.
	Transport Transport
	// Command is the binary executed for stdio transports.
	Command string
	// Args is the command-line arguments for stdio transports.
	Args []string
	// URL is the endpoint for HTTP-based transports.
	URL string
	// EnvVarNames is the names (not values) of env vars referenced.
	EnvVarNames []string
	// HeaderNames is the names (not values) of HTTP headers referenced.
	HeaderNames []string
	// AllowedTools is the explicit tool allowlist if configured.
	AllowedTools []string
	// AllowedResources is the explicit resource allowlist if configured.
	AllowedResources []string
}

// AgentDetail mirrors proto VetInventoryEvent.AgentDetail. Populated only
// when Kind == KindCodingAgent.
type AgentDetail struct {
	// Version is the agent's reported version, when available.
	Version string
	// PermissionMode is the agent's configured permission mode.
	PermissionMode string
	// InstructionFiles is the set of instruction files driving the agent.
	InstructionFiles []string
	// Model is the configured LLM model identifier.
	Model string
	// APIKeyEnvName is the env var name (not value) holding the API key.
	APIKeyEnvName string
}

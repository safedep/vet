# AI Tool Discovery Specification

## Overview

This spec defines how `vet` discovers AI coding agents, MCP servers, AI extensions, and other AI tools configured on a local system. The goal is **inventory and audit** — enumerate what's installed, where it's configured, and what permissions/access it has. Risk analysis and enrichment are out of scope for v1 but the design supports future extension through `pkg/analyzer/`.

## Design Principles

1. **Pluggable architecture** — Adding a new AI tool discoverer requires implementing a single interface
2. **New model, not shoehorned into Package** — AI tools have fundamentally different attributes than packages (config paths, commands, env vars, transport, permissions)
3. **Callback-based enumeration** — Matches the existing `PackageManifestReader` pattern. Discoverers stream results through a handler function
4. **System + project level** — Discover both global AI tool configs (`~/.claude/`, `~/.cursor/`) and project-level configs (`.mcp.json`, `.cursorrules`)
5. **Security-relevant field extraction** — Parse env var names (not values), tool permissions, file paths, commands, and trust boundaries
6. **Secrets never collected** — The discovery system must never read, store, log, or serialize secret values. This is enforced by the discoverer contract and by model design (no fields exist that could hold raw config with embedded secrets).

## Security Model

This section defines the security properties of the AI tool discovery system. The discovery process reads local configuration files that routinely contain secrets (API keys, tokens, database connection strings). The system MUST NOT become a vector for leaking those secrets through reports, logs, serialized output, or the model itself.

### Threat: Secret Leakage via Discovery Output

AI tool config files (`.mcp.json`, `settings.json`, etc.) contain `env` blocks with secret values:
```json
{ "env": { "ANTHROPIC_API_KEY": "sk-ant-...", "DB_PASSWORD": "hunter2" } }
```

If any part of the discovery pipeline captures these values, they will flow into JSON reports, console output, SARIF files, and potentially cloud sync — exposing credentials.

### Mitigation: No Secret-Capable Fields in Model

The `AITool` model has **no field that can hold raw config data**. There is no `RawConfig`, no `map[string]any` dump of the original file. Every field is purpose-designed:

- `EnvVarNames []string` — Key names only. Discoverers MUST extract only the map keys from `env` blocks, never the values.
- `HeaderNames []string` — Key names only. Same rule.
- `APIKeyEnvName string` — The environment variable name (e.g. `"ANTHROPIC_API_KEY"`), never the resolved value.
- `Args []string` — Command arguments. See argument sanitization rules below.
- `Metadata map[string]any` — Generic store. Subject to the discoverer contract below.

### Discoverer Contract (MUST Rules)

Every `AIToolReader` implementation MUST adhere to these rules. Violations are treated as security bugs.

| # | Rule | Rationale |
|---|---|---|
| S1 | **MUST NOT** store environment variable values in any field | Env vars contain API keys, tokens, passwords |
| S2 | **MUST NOT** store HTTP header values in any field | Headers contain auth tokens, session cookies |
| S3 | **MUST NOT** log secret values at any log level (including debug) | Log output is not access-controlled |
| S4 | **MUST** redact argument values that match secret patterns before storing in `Args` | Commands like `--token=xxx` embed secrets in args |
| S5 | **MUST NOT** store file contents in `Metadata` | Config files contain secrets; store paths not contents |
| S6 | **MUST NOT** resolve or evaluate environment variable references | `$API_KEY` must remain as a name, not resolved to its value |
| S7 | **MUST** treat `Metadata` values as potentially visible in reports | Only store values safe for display: paths, names, booleans, counts |

### Argument Sanitization (Rule S4)

MCP server arguments may contain inline secrets. Discoverers MUST apply sanitization before storing `Args`:

```go
// Patterns to redact in argument values
var argSecretPatterns = []string{
    `--token=`,
    `--api-key=`,
    `--password=`,
    `--secret=`,
    `--credentials=`,
}

// Redacted form: ["--token=<REDACTED>"] not ["--token=sk-ant-..."]
```

Arguments that are positional (not key=value) are generally safe to store (e.g., `["-y", "@anthropic/mcp-server"]`). The sanitizer targets `--key=value` patterns where the value portion may be a secret.

### Metadata Safety

The `Metadata map[string]any` field is a generic store. Since it accepts `any`, it's a potential vector for accidental secret storage. The discoverer contract (S5, S7) governs what may be stored. Acceptable metadata values:

- File paths, directory names
- Boolean flags, integer counts
- Timestamps, version strings
- Permission mode names
- Config file stat info (mode bits, size) — but NOT file contents

Unacceptable metadata values:
- File contents (even partial)
- Environment variable values
- Token/key strings
- URL query parameters that may contain auth tokens

### Review Checklist for New Discoverers

When reviewing a PR that adds a new `AIToolReader`:

- [ ] Does it read `env` blocks? Verify only keys are extracted.
- [ ] Does it store command args? Verify secret patterns are redacted.
- [ ] Does it write to `Metadata`? Verify no file contents or secret values.
- [ ] Does it log config data? Verify no secret values at any level.
- [ ] Does it resolve env var references? It must not.

## Package Structure

```
pkg/aitool/                  # Core library: models, interfaces, discoverers
├── model.go                 # AITool, MCPServerConfig, AgentConfig, AIToolInventory
├── reader.go                # AIToolReader interface and AIToolHandlerFn
├── registry.go              # Discoverer registry (pluggable architecture)
│
│   # Config-based discoverers (parse config files for MCP servers + agent settings)
├── claude_code.go           # Claude Code config discoverer
├── cursor.go                # Cursor config discoverer
│
│   # CLI tool discoverers (binary lookup + verified identity)
├── cli_common.go            # CLIToolVerifier interface + ProbeAndVerify shared logic
├── claude_cli.go            # Claude Code CLI binary verifier
├── aider.go                 # Aider binary verifier
├── gh_copilot.go            # GitHub Copilot (gh extension) verifier
├── amazon_q.go              # Amazon Q binary verifier
│
│   # IDE extension discoverer (bridges vsix reader)
├── ai_extension.go          # AI IDE extension detection
├── known_extensions.go      # Curated map of known AI extension IDs
│
├── fixtures/                # Test fixture config files
└── *_test.go                # Tests per discoverer

cmd/ai/                      # CLI command: `vet ai`
├── main.go                  # NewAICommand() parent command
└── discover.go              # `vet ai discover` subcommand + flag wiring
```

## Models (`model.go`)

### AIToolType

```go
type AIToolType string

const (
    AIToolTypeMCPServer   AIToolType = "mcp_server"
    AIToolTypeCodingAgent AIToolType = "coding_agent"
    AIToolTypeAIExtension AIToolType = "ai_extension"
    AIToolTypeCLITool     AIToolType = "cli_tool"
)
```

### AIToolScope

Distinguishes system-level (global) from project-level (repo-scoped) configs.

```go
type AIToolScope string

const (
    AIToolScopeSystem  AIToolScope = "system"   // ~/.claude/, ~/.cursor/
    AIToolScopeProject AIToolScope = "project"  // .mcp.json, .cursorrules in a repo
)
```

### MCPTransport

```go
type MCPTransport string

const (
    MCPTransportStdio          MCPTransport = "stdio"
    MCPTransportSSE            MCPTransport = "sse"
    MCPTransportStreamableHTTP MCPTransport = "streamable_http"
)
```

### AITool — Core model

```go
// AITool represents a discovered AI tool, MCP server, or coding agent
// configured on the local system or within a project.
type AITool struct {
    // Unique identifier for this tool within the inventory.
    // Generated deterministically from (host, type, scope, name, config_path)
    // so the same tool produces the same ID across runs.
    ID string `json:"id"`

    // SourceID groups tools that were discovered from the same config source.
    // For example, a Claude Code coding_agent entry and all MCP servers parsed
    // from ~/.claude/settings.json share the same SourceID. This enables
    // reporters to reconstruct the relationship: "Claude Code → its MCP servers".
    //
    // Generated deterministically from (host, config_path) so tools from
    // the same file always share a SourceID.
    SourceID string `json:"source_id"`

    // Human-readable name of this tool (e.g. "safedep" MCP server, "Claude Code")
    Name string `json:"name"`

    // Type classification
    Type AIToolType `json:"type"`

    // Whether this is a system-level or project-level config
    Scope AIToolScope `json:"scope"`

    // The AI client/host that owns this config (e.g. "claude_code", "cursor")
    Host string `json:"host"`

    // Filesystem path to the config file where this tool was discovered
    ConfigPath string `json:"config_path"`

    // MCP server-specific configuration (nil for non-MCP tools)
    MCPServer *MCPServerConfig `json:"mcp_server,omitempty"`

    // Agent-specific configuration (nil for non-agent tools)
    Agent *AgentConfig `json:"agent,omitempty"`

    // Enabled state if detectable from config
    Enabled *bool `json:"enabled,omitempty"`

    // Metadata is a generic key-value store for discoverer-specific or
    // host-specific information that doesn't warrant a strongly typed field.
    // Examples: detected shell, project name from config, custom tags,
    // discoverer-added annotations, file permissions on config path, etc.
    // Keys should use namespaced dot notation (e.g. "claude_code.project_name",
    // "discovery.timestamp") to avoid collisions across discoverers.
    //
    // SECURITY: Subject to discoverer contract rules S5 and S7. Must not
    // contain file contents, secret values, or resolved env var values.
    Metadata map[string]any `json:"metadata,omitempty"`
}
```

### MCPServerConfig — MCP-specific details

```go
// MCPServerConfig holds configuration details for a discovered MCP server.
type MCPServerConfig struct {
    // Transport protocol
    Transport MCPTransport `json:"transport"`

    // Command to launch the server (stdio transport)
    Command string `json:"command,omitempty"`

    // Arguments passed to the command
    Args []string `json:"args,omitempty"`

    // URL for remote transports (SSE, streamable HTTP)
    URL string `json:"url,omitempty"`

    // Environment variable names configured for this server
    // Values are NOT captured for security — only the key names
    EnvVarNames []string `json:"env_var_names,omitempty"`

    // Headers configured (key names only, not values)
    HeaderNames []string `json:"header_names,omitempty"`

    // Tool permissions / allowed tools if specified in config
    AllowedTools []string `json:"allowed_tools,omitempty"`

    // Resource permissions if specified
    AllowedResources []string `json:"allowed_resources,omitempty"`
}
```

### AgentConfig — Coding agent details

```go
// AgentConfig holds configuration details for a discovered AI coding agent.
type AgentConfig struct {
    // Version of the agent if detectable
    Version string `json:"version,omitempty"`

    // Permission mode (e.g. "auto", "manual", "supervised")
    PermissionMode string `json:"permission_mode,omitempty"`

    // Custom instructions file paths (CLAUDE.md, .cursorrules, etc.)
    InstructionFiles []string `json:"instruction_files,omitempty"`

    // Model configuration if specified
    Model string `json:"model,omitempty"`

    // API key env var name (NOT the value)
    APIKeyEnvName string `json:"api_key_env_name,omitempty"`
}
```

### AITool Metadata Helpers

```go
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
```

Discoverers use namespaced keys to avoid collisions:

| Key pattern | Example | Set by |
|---|---|---|
| `{host}.*` | `claude_code.project_name` | Host-specific discoverer |
| `discovery.*` | `discovery.timestamp`, `discovery.config_file_mode` | Any discoverer |
| `risk.*` | `risk.notes`, `risk.manual_override` | Future analyzer/policy layer |

### ID Generation

IDs are deterministic hashes so the same tool produces the same ID across runs. This uses the same `hash/fnv` approach as `models.Package.Id()`.

```go
import (
    "fmt"
    "hash/fnv"
    "strconv"
    "strings"
)

// GenerateID produces a deterministic ID for an AITool from its identity fields.
func GenerateID(host, toolType, scope, name, configPath string) string {
    data := fmt.Sprintf("%s/%s/%s/%s/%s",
        strings.ToLower(host),
        strings.ToLower(toolType),
        strings.ToLower(scope),
        strings.ToLower(name),
        strings.ToLower(configPath))
    h := fnv.New64a()
    h.Write([]byte(data))
    return strconv.FormatUint(h.Sum64(), 16)
}

// GenerateSourceID produces a deterministic source grouping ID.
// Tools from the same host + config file share a SourceID.
func GenerateSourceID(host, configPath string) string {
    data := fmt.Sprintf("%s/%s",
        strings.ToLower(host),
        strings.ToLower(configPath))
    h := fnv.New64a()
    h.Write([]byte(data))
    return strconv.FormatUint(h.Sum64(), 16)
}
```

Discoverers call these when constructing each `AITool`:

```go
tool := &AITool{
    Name:       "safedep",
    Type:       AIToolTypeMCPServer,
    Scope:      AIToolScopeProject,
    Host:       "claude_code",
    ConfigPath: "/Users/dev/project/.mcp.json",
}
tool.ID = GenerateID(tool.Host, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
tool.SourceID = GenerateSourceID(tool.Host, tool.ConfigPath)
```

### Relationship Queries via SourceID

SourceID enables reconstructing the ownership graph without explicit parent references:

```go
// "What MCP servers belong to this Claude Code instance?"
//
// 1. Find the coding_agent for Claude Code:
//    agent := inventory.FilterByType(AIToolTypeCodingAgent)
//              .FilterByHost("claude_code")[0]
//
// 2. Find all tools from the same config source:
//    siblings := inventory.FilterBySourceID(agent.SourceID)
//
// 3. The siblings with type=mcp_server are Claude Code's MCP servers.
```

Cross-file relationships also work. Claude Code may have MCP servers in multiple config files:

```
~/.claude/settings.json    → SourceID "a1b2" (agent + system MCP servers)
project/.mcp.json          → SourceID "c3d4" (project MCP servers)
project/.claude/settings.json → SourceID "e5f6" (project-scoped settings MCP servers)
```

All share `Host == "claude_code"`, so `FilterByHost("claude_code")` returns the complete picture. SourceID adds the finer granularity of "which config file group".

### AIToolInventory — Aggregate result (optional convenience wrapper)

```go
// AIToolInventory is a convenience wrapper for collecting all discovered tools.
// Useful for reporters that need the full picture.
type AIToolInventory struct {
    Tools []*AITool `json:"tools"`
}

func (inv *AIToolInventory) Add(tool *AITool) {
    inv.Tools = append(inv.Tools, tool)
}

func (inv *AIToolInventory) FilterByType(t AIToolType) []*AITool { ... }
func (inv *AIToolInventory) FilterByHost(host string) []*AITool { ... }
func (inv *AIToolInventory) FilterByScope(scope AIToolScope) []*AITool { ... }
func (inv *AIToolInventory) FilterBySourceID(sourceID string) []*AITool { ... }

// GroupByHost returns tools grouped by host name.
// Useful for reporters that render per-host sections.
func (inv *AIToolInventory) GroupByHost() map[string][]*AITool { ... }

// GroupBySourceID returns tools grouped by source config.
// Useful for rendering "config file → tools from that file".
func (inv *AIToolInventory) GroupBySourceID() map[string][]*AITool { ... }
```

## Reader Interface (`reader.go`)

```go
// AIToolHandlerFn is called for each discovered AI tool.
// Return an error to stop enumeration.
type AIToolHandlerFn func(*AITool) error

// AIToolReader discovers AI tools from a specific source.
// Implementations should be specific to a single AI client/host
// (e.g. one reader for Claude Code, another for Cursor).
type AIToolReader interface {
    // Name returns a human-readable name for this discoverer
    Name() string

    // Host returns the AI client identifier (e.g. "claude_code", "cursor")
    Host() string

    // EnumTools discovers AI tools and calls handler for each one found.
    // Enumeration stops on first handler error.
    EnumTools(handler AIToolHandlerFn) error
}
```

## Registry (`registry.go`)

The registry enables the pluggable architecture. New discoverers register themselves and the scan orchestrator iterates all registered readers.

```go
// AIToolDiscovererFactory creates a reader given a config.
// The config provides context like the project directory path
// for project-level discovery.
type AIToolDiscovererFactory func(config DiscoveryConfig) (AIToolReader, error)

type DiscoveryConfig struct {
    // HomeDir overrides the user home directory (for testing)
    HomeDir string

    // ProjectDir is the project root for project-level discovery.
    // Empty string means skip project-level discovery.
    ProjectDir string
}

// Registry maps host names to their discoverer factories.
// Calling Register() adds a new discoverer.
// Calling Discover() runs all registered discoverers.
type Registry struct { ... }

func NewRegistry() *Registry
func (r *Registry) Register(name string, factory AIToolDiscovererFactory)
func (r *Registry) Discover(config DiscoveryConfig, handler AIToolHandlerFn) error
```

A default registry with all built-in discoverers:

```go
func DefaultRegistry() *Registry {
    r := NewRegistry()
    // Config-based discoverers (MCP servers + agent configs)
    r.Register("claude_code_config", NewClaudeCodeDiscoverer)
    r.Register("cursor_config", NewCursorDiscoverer)
    // CLI tool discoverers (binary lookup + verified identity)
    r.Register("claude_code_cli", NewClaudeCLIDiscoverer)
    r.Register("aider", NewAiderDiscoverer)
    r.Register("gh_copilot", NewGhCopilotDiscoverer)
    r.Register("amazon_q", NewAmazonQDiscoverer)
    // IDE extension discoverer
    r.Register("ide_extensions", NewAIExtensionDiscoverer)
    return r
}
```

## Discoverers

### Claude Code (`claude_code.go`)

**Host:** `claude_code`

**System-level paths:**
- `~/.claude/settings.json` — Global settings (permissions, model, etc.)
- `~/.claude/projects/` — Per-project settings with MCP configs

**Project-level paths (relative to project root):**
- `.mcp.json` — MCP server definitions
- `.claude/settings.json` — Project-scoped Claude Code settings
- `CLAUDE.md` — Custom instructions file

**Config file formats:**

`.mcp.json` (project-level MCP servers):
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@some/mcp-server"],
      "env": { "API_KEY": "..." },
      "type": "stdio"
    }
  }
}
```

`~/.claude/settings.json` (global settings):
```json
{
  "permissions": { ... },
  "mcpServers": { ... },
  "model": "claude-sonnet-4-20250514"
}
```

**Discovery logic:**

1. Parse `~/.claude/settings.json` → emit one `AIToolTypeCodingAgent` for Claude Code itself + one `AIToolTypeMCPServer` per MCP server entry
2. Walk `~/.claude/projects/*/settings.json` → emit `AIToolTypeMCPServer` for each project-scoped MCP server (scope=project, config_path points to the project settings)
3. If `ProjectDir` is set:
   - Parse `{ProjectDir}/.mcp.json` → emit `AIToolTypeMCPServer` per entry
   - Parse `{ProjectDir}/.claude/settings.json` → emit project-scoped MCP servers
   - Check for `{ProjectDir}/CLAUDE.md` → include in agent's `InstructionFiles`

### Cursor (`cursor.go`)

**Host:** `cursor`

**System-level paths:**
- `~/.cursor/mcp.json` — Global MCP server configs
- `~/.cursor/extensions/extensions.json` — AI extensions (already covered by vsix reader, but we re-read for AI-specific extensions)

**Project-level paths:**
- `.cursor/mcp.json` — Project-scoped MCP server configs
- `.cursorrules` — Custom instructions file
- `.cursor/rules/` — Directory of rule files

**Config file formats:**

`~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "server-name": {
      "command": "node",
      "args": ["server.js"],
      "env": { "TOKEN": "..." }
    }
  }
}
```

**Discovery logic:**

1. Parse `~/.cursor/mcp.json` → emit `AIToolTypeMCPServer` per server entry (scope=system)
2. Emit one `AIToolTypeCodingAgent` for Cursor itself with detected config
3. If `ProjectDir` is set:
   - Parse `{ProjectDir}/.cursor/mcp.json` → emit `AIToolTypeMCPServer` per entry (scope=project)
   - Check for `{ProjectDir}/.cursorrules` → include in agent's `InstructionFiles`
   - Scan `{ProjectDir}/.cursor/rules/` → include rule files in `InstructionFiles`

### AI CLI Tool Discoverers (Plugin-per-tool)

Each AI CLI tool gets its own discoverer plugin that implements `AIToolReader`. Detection is **never based solely on binary name in PATH** — every discoverer must verify the tool's identity via version output signature, config file presence, or other tool-specific proof.

#### Design: CLIToolDiscoverer Base

A shared base handles the common pattern of binary lookup + verified execution. Individual plugins provide the tool-specific identity verification.

```go
// CLIToolVerifier is implemented by each AI CLI tool plugin.
// It defines how to find and verify the tool's identity.
type CLIToolVerifier interface {
    // BinaryNames returns candidate binary names to search in PATH.
    // Multiple names handle platform differences (e.g., ["claude", "claude-code"]).
    BinaryNames() []string

    // VerifyArgs returns the arguments to execute for identity verification.
    // Typically ["--version"] or ["version"].
    VerifyArgs() []string

    // VerifyOutput checks the command output and confirms this is the expected tool.
    // Returns (version string, true) if verified, ("", false) if not the right tool.
    // This is the critical function that prevents false positives.
    VerifyOutput(stdout, stderr string) (version string, verified bool)

    // DisplayName returns the human-readable name for reporting.
    DisplayName() string

    // Host returns the discoverer host identifier.
    Host() string
}
```

**Verification rules (MUST):**

| # | Rule |
|---|---|
| V1 | A tool MUST NOT be reported if `VerifyOutput` returns `verified=false` |
| V2 | `VerifyOutput` MUST match a specific signature string in the output, not just "any output" |
| V3 | If the verification command times out (5s) or fails to execute, the tool MUST NOT be reported |
| V4 | Only the arguments from `VerifyArgs()` may be executed. Never execute arbitrary flags. |

#### Plugin: Aider (`aider.go`)

**Host:** `aider`

```go
type aiderDiscoverer struct{}

func (d *aiderDiscoverer) BinaryNames() []string   { return []string{"aider"} }
func (d *aiderDiscoverer) VerifyArgs() []string     { return []string{"--version"} }
func (d *aiderDiscoverer) DisplayName() string      { return "Aider" }
func (d *aiderDiscoverer) Host() string             { return "aider" }

func (d *aiderDiscoverer) VerifyOutput(stdout, stderr string) (string, bool) {
    // aider --version outputs: "aider v0.82.1"
    re := regexp.MustCompile(`aider\s+v?(\d+\.\d+\.\d+)`)
    if m := re.FindStringSubmatch(stdout); len(m) > 1 {
        return m[1], true
    }
    return "", false
}
```

**Additional discovery:** If verified, also check for `~/.aider.conf.yml` and emit config details via Metadata.

#### Plugin: GitHub Copilot CLI (`gh_copilot.go`)

**Host:** `gh_copilot`

GitHub Copilot CLI is a `gh` extension, not a standalone binary. Requires special verification.

```go
func (d *ghCopilotDiscoverer) BinaryNames() []string { return []string{"gh"} }
func (d *ghCopilotDiscoverer) VerifyArgs() []string   { return []string{"extension", "list"} }

func (d *ghCopilotDiscoverer) VerifyOutput(stdout, stderr string) (string, bool) {
    // gh extension list outputs lines like: "gh copilot  github/gh-copilot  v1.0.5"
    for _, line := range strings.Split(stdout, "\n") {
        if strings.Contains(line, "github/gh-copilot") {
            re := regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)
            if m := re.FindStringSubmatch(line); len(m) > 1 {
                return m[1], true
            }
            return "", true // present but version not parseable
        }
    }
    return "", false // gh exists but copilot extension not installed
}
```

#### Plugin: Amazon Q (`amazon_q.go`)

**Host:** `amazon_q`

```go
func (d *amazonQDiscoverer) BinaryNames() []string { return []string{"q", "amazon-q"} }
func (d *amazonQDiscoverer) VerifyArgs() []string   { return []string{"--version"} }

func (d *amazonQDiscoverer) VerifyOutput(stdout, stderr string) (string, bool) {
    // Verify output contains "Amazon Q" or "aws" signature
    combined := stdout + stderr
    if !strings.Contains(strings.ToLower(combined), "amazon") &&
       !strings.Contains(strings.ToLower(combined), "aws") {
        return "", false // binary named 'q' but not Amazon Q
    }
    re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
    if m := re.FindStringSubmatch(combined); len(m) > 1 {
        return m[1], true
    }
    return "", true
}
```

This is a good example of why per-tool verification matters — `q` is a common binary name.

#### Plugin: Claude Code CLI (`claude_cli.go`)

**Host:** `claude_code` (same host as config discoverer — they share a host)

```go
func (d *claudeCLIDiscoverer) BinaryNames() []string { return []string{"claude"} }
func (d *claudeCLIDiscoverer) VerifyArgs() []string   { return []string{"--version"} }

func (d *claudeCLIDiscoverer) VerifyOutput(stdout, stderr string) (string, bool) {
    // claude --version outputs: "claude v1.0.x" or "Claude Code v1.0.x"
    combined := stdout + stderr
    re := regexp.MustCompile(`(?i)claude[^\d]*v?(\d+\.\d+\.\d+)`)
    if m := re.FindStringSubmatch(combined); len(m) > 1 {
        return m[1], true
    }
    return "", false
}
```

Note: The Claude Code config discoverer (`claude_code.go`) and CLI discoverer share `host="claude_code"`. The config discoverer finds MCP servers and agent settings; the CLI discoverer confirms the binary is installed and captures the version. Both contribute to the full picture of "Claude Code on this system".

#### v1 CLI Tool Plugins

| Plugin file | Host | Binary names | Verification signature |
|---|---|---|---|
| `claude_cli.go` | `claude_code` | `claude` | `claude` + semver in output |
| `aider.go` | `aider` | `aider` | `aider` + semver in output |
| `gh_copilot.go` | `gh_copilot` | `gh` | `github/gh-copilot` in extension list |
| `amazon_q.go` | `amazon_q` | `q`, `amazon-q` | `amazon` or `aws` in output |

**Future CLI tool plugins (not in v1):**

| Plugin | Host | Binary | Verification |
|---|---|---|---|
| `cody.go` | `cody` | `cody` | `sourcegraph` or `cody` signature |
| `continue_cli.go` | `continue` | `continue` | `continue` + version signature (avoid false positive with shell builtin) |
| `tabnine_cli.go` | `tabnine` | `tabnine` | `tabnine` signature |
| `windsurf_cli.go` | `windsurf` | `windsurf` | `windsurf` or `codeium` signature |

#### Shared Execution Logic (`cli_common.go`)

The common execution wrapper handles timeouts, error handling, and the verify-then-emit pattern:

```go
const cliProbeTimeout = 5 * time.Second

// ProbeAndVerify runs a CLI tool discoverer through the standard
// lookup → execute → verify → emit pipeline.
func ProbeAndVerify(verifier CLIToolVerifier, handler AIToolHandlerFn) error {
    for _, name := range verifier.BinaryNames() {
        binPath, err := exec.LookPath(name)
        if err != nil {
            continue
        }

        ctx, cancel := context.WithTimeout(context.Background(), cliProbeTimeout)
        defer cancel()

        cmd := exec.CommandContext(ctx, binPath, verifier.VerifyArgs()...)
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        err = cmd.Run()
        if err != nil {
            // Command failed or timed out — do NOT report the tool
            continue
        }

        version, verified := verifier.VerifyOutput(stdout.String(), stderr.String())
        if !verified {
            // Binary exists but is NOT the expected AI tool
            continue
        }

        tool := &AITool{
            Name:       verifier.DisplayName(),
            Type:       AIToolTypeCLITool,
            Scope:      AIToolScopeSystem,
            Host:       verifier.Host(),
            ConfigPath: binPath,
        }
        tool.ID = GenerateID(tool.Host, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
        tool.SourceID = GenerateSourceID(tool.Host, tool.ConfigPath)

        if version != "" {
            tool.SetMeta("binary.version", version)
        }
        tool.SetMeta("binary.path", binPath)
        tool.SetMeta("binary.verified", true)

        return handler(tool)
    }
    return nil // none of the candidate binaries matched
}
```

Each CLI tool discoverer's `EnumTools` simply delegates:

```go
func (d *aiderDiscoverer) EnumTools(handler AIToolHandlerFn) error {
    return ProbeAndVerify(d, handler)
}
```

### AI IDE Extension Discoverer (`ai_extension.go`)

**Host:** `ide_extensions`

Bridges the existing `pkg/readers/vsix_ext_reader.go` to surface AI-specific IDE extensions in the `vet ai discover` output. Uses a curated list of known AI extension IDs to filter from the full extension list. Unlike binary probing, IDE extension IDs are exact-match identifiers assigned by the marketplace — no false positive risk from name collisions.

**Known AI extension IDs (v1):**

| Extension ID | Display Name | IDE |
|---|---|---|
| `github.copilot` | GitHub Copilot | VS Code, Cursor |
| `github.copilot-chat` | GitHub Copilot Chat | VS Code, Cursor |
| `sourcegraph.cody-ai` | Cody | VS Code |
| `continue.continue` | Continue | VS Code, Cursor |
| `tabnine.tabnine-vscode` | Tabnine | VS Code |
| `amazonwebservices.amazon-q-vscode` | Amazon Q | VS Code |
| `saoudrizwan.claude-dev` | Cline | VS Code, Cursor |
| `rooveterinaryinc.roo-cline` | Roo Code | VS Code, Cursor |
| `codeium.codeium` | Codeium / Windsurf | VS Code |
| `supermaven.supermaven` | Supermaven | VS Code |

**Discovery logic:**

1. Use `readers.NewVSIXExtReaderFromDefaultDistributions()` to enumerate all IDE extensions across installed editors (VS Code, Cursor, Windsurf, VSCodium)
2. Filter extensions against the known AI extension ID set (exact match, case-insensitive)
3. For each match, emit an `AIToolTypeAIExtension` entry

```go
func (d *aiExtensionDiscoverer) EnumTools(handler AIToolHandlerFn) error {
    vsixReader, err := readers.NewVSIXExtReaderFromDefaultDistributions()
    if err != nil {
        return nil // no IDE extensions found, not an error
    }

    return vsixReader.EnumManifests(func(manifest *models.PackageManifest, pr readers.PackageReader) error {
        return pr.EnumPackages(func(pkg *models.Package) error {
            info, ok := knownAIExtensions[strings.ToLower(pkg.Name)]
            if !ok {
                return nil // not an AI extension
            }

            tool := &AITool{
                Name:       info.DisplayName,
                Type:       AIToolTypeAIExtension,
                Scope:      AIToolScopeSystem,
                Host:       "ide_extensions",
                ConfigPath: manifest.GetPath(),
            }
            tool.ID = GenerateID(tool.Host, string(tool.Type), string(tool.Scope), pkg.Name, tool.ConfigPath)
            tool.SourceID = GenerateSourceID(tool.Host, tool.ConfigPath)
            tool.SetMeta("extension.id", pkg.Name)
            tool.SetMeta("extension.version", pkg.Version)
            tool.SetMeta("extension.ecosystem", string(manifest.Ecosystem))

            return handler(tool)
        })
    })
}
```

### Discovery Method Summary

| Method | What it finds | Tool type | False positive prevention |
|---|---|---|---|
| **Config file parsing** | MCP servers, agent configs | `mcp_server`, `coding_agent` | Config at known path = definitive proof |
| **CLI tool plugins** | AI CLI tools installed on system | `cli_tool` | Binary found + output signature verified |
| **IDE extension bridging** | AI extensions in VS Code/Cursor/etc | `ai_extension` | Marketplace extension ID exact match |

All three methods run by default when `vet ai discover` is invoked. Together they answer: **"What AI tools are installed and configured on this system?"**

**Key invariant:** No tool is ever reported based solely on a file path or binary name. Every discoverer must have a verification step that confirms the tool's identity.

## Future Discoverers (not in v1, but the registry supports them)

**Config-based discoverers:**

| Host | System Config Paths | Project Config Paths |
|---|---|---|
| `vscode_copilot` | `~/.vscode/settings.json` | `.vscode/settings.json`, `.vscode/mcp.json` |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | `.windsurf/mcp.json`, `.windsurfrules` |
| `zed` | `~/.config/zed/settings.json` | `.zed/settings.json` |
| `continue` | `~/.continue/config.json` | `.continue/config.json` |
| `claude_desktop` | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) | N/A |

**Additional detection methods (future):**

| Method | What it finds | Notes |
|---|---|---|
| Process scanning (`ps`) | Running AI tool processes | Runtime detection, not just installed |
| Homebrew query | AI tools installed via brew | Bridge `brew_reader.go` similar to vsix bridge |
| pip/npm global list | AI tools installed as global packages | `aider-chat` via pip, `@anthropic/claude-code` via npm |

## Integration Points

### With existing `pkg/readers/`

The `AIToolReader` is intentionally **not** a `PackageManifestReader`. They are separate contracts. The AI extension discoverer bridges `vsix_ext_reader.go` by using it as an internal dependency, not by implementing `PackageManifestReader`. A future bridge adapter could extract npm/pip package references from MCP server commands (e.g., `npx @some/mcp-server` → `npm:@some/mcp-server`) and feed them into the existing enrichment pipeline.

### With `pkg/reporter/`

The existing `Reporter` interface accepts `PackageManifest`. For AI tool reporting, extend with a new interface:

```go
// AIToolReporter can be implemented alongside Reporter
// by reporting modules that support AI tool inventory output.
type AIToolReporter interface {
    AddAITool(tool *AITool)
    FinishAITools() error
}
```

Reporters that want to support AI tools implement both `Reporter` and `AIToolReporter`. This is backward-compatible — existing reporters are unaffected.

### With `pkg/analyzer/filterv2/` — Future Policy Engine for AI Tools

> **Out of scope for v1.** The model is explicitly designed to support this path.

The existing `filterv2` package implements a CEL-based policy engine for packages. It compiles `policyv1.Rule` expressions into `cel.Program` instances and evaluates them against a `policyv1.Input` protobuf built from `models.Package`. The same pattern can be extended for AI tool policy evaluation.

#### Approach: AITool Policy Evaluator

A parallel evaluator (e.g., `pkg/analyzer/aitoolfilter/`) would follow the same architecture as `filterv2`:

```go
// Mirrors filterv2.Evaluator but operates on AITool instead of Package
type AIToolEvaluator interface {
    AddPolicy(policy *policyv1.Policy) error
    EvaluateAITool(tool *aitool.AITool) (*AIToolEvaluationResult, error)
}
```

The evaluator would:
1. Create a CEL environment with AI tool-specific variables and types
2. Compile policy rules into `cel.Program` (same as `filterv2.FilterProgram`)
3. Build an AI tool policy input (analogous to `filterv2.buildPolicyInput`)
4. Evaluate rules and return match results

#### CEL Variable Bindings for AI Tools

Following the filterv2 pattern of registering protobuf types and named variables:

```go
// Policy input variable names for AI tool CEL expressions
const (
    aiToolInputVarRoot      = "aitool"
    aiToolInputVarMCPServer = "mcp"
    aiToolInputVarAgent     = "agent"
    aiToolInputVarMetadata  = "meta"
)
```

The `meta` variable exposes `AITool.Metadata` as a `map<string, dyn>` in CEL, making discoverer-specific and user-annotated metadata available to policy rules without requiring schema changes.

#### Example Policy Rules

**Configuration weakness detection:**
```cel
# Flag MCP servers using stdio transport with no allowed_tools restriction
aitool.type == "mcp_server"
  && mcp.transport == "stdio"
  && mcp.allowed_tools.size() == 0

# Flag MCP servers with database-related env vars (data exposure risk)
aitool.type == "mcp_server"
  && mcp.env_var_names.exists(v,
       v.contains("DB_") || v.contains("DATABASE") || v.contains("CONNECTION_STRING"))

# Flag remote MCP servers (SSE/HTTP) — network trust boundary
aitool.type == "mcp_server"
  && (mcp.transport == "sse" || mcp.transport == "streamable_http")

# Flag coding agents running with permissive modes
aitool.type == "coding_agent"
  && agent.permission_mode == "auto"
```

**Inventory compliance policies:**
```cel
# Require all project-level MCP servers to be from approved list
aitool.scope == "project"
  && aitool.type == "mcp_server"
  && !(aitool.name in ["safedep", "postgres", "github"])

# Flag AI tools from unknown hosts
!(aitool.host in ["claude_code", "cursor", "vscode_copilot"])
```

**Metadata-driven policies (using generic Metadata store):**
```cel
# Flag tools where discoverer recorded a world-writable config file
has(meta["discovery.config_file_mode"])
  && meta["discovery.config_file_mode"] == "0777"

# Org-specific: require an internal approval tag in metadata
aitool.scope == "project"
  && !has(meta["org.approved"])
```

**Supply chain risk (future, with package extraction bridge):**
```cel
# Flag MCP servers running unvetted npm packages via npx
aitool.type == "mcp_server"
  && mcp.command == "npx"
  && mcp.args.size() > 0
```

#### Protobuf Schema Direction

Like `filterv2` which uses `safedep.messages.policy.v1.Input`, AI tool policy evaluation would benefit from a protobuf definition for the policy input. This enables:
- Type-safe CEL compilation with `cel.Types()`
- Enum constants for `AIToolType`, `MCPTransport`, `AIToolScope` (same pattern as `filterv2`'s `Ecosystem` and `ProjectSourceType` enum maps)
- Stable contract between discovery and evaluation

```protobuf
// Future: safedep.messages.policy.v1.AIToolInput
message AIToolInput {
    string name = 1;
    AIToolType type = 2;
    AIToolScope scope = 3;
    string host = 4;
    MCPServerInput mcp_server = 5;
    AgentInput agent = 6;
}
```

#### Risk Categories to Analyze

The policy engine should support detecting these risk categories:

| Category | Description | Example Rule |
|---|---|---|
| **Overprivileged MCP** | MCP servers with no tool/resource restrictions | `mcp.allowed_tools.size() == 0` |
| **Sensitive data exposure** | Env vars suggesting DB, API key, or credential access | `mcp.env_var_names.exists(v, v.contains("SECRET"))` |
| **Network trust boundary** | Remote MCP servers (SSE/HTTP) vs local stdio | `mcp.transport != "stdio"` |
| **Unvetted packages** | MCP servers launched via `npx`/`uvx` with unscanned packages | `mcp.command in ["npx", "uvx", "pipx"]` |
| **Permissive agent config** | Agents with auto-approve or broad permissions | `agent.permission_mode == "auto"` |
| **Shadow AI tooling** | Unauthorized AI tools in project configs | `aitool.scope == "project" && !(aitool.host in approved_hosts)` |
| **Instruction injection surface** | Custom instruction files writable by others | Detection via file permission checks |

### With CLI commands

See [CLI Experience](#cli-experience) section below for the full design.

## CLI Experience

### Command Hierarchy

AI tool discovery lives under a new `vet ai` top-level command, separate from the SCA pipeline (`vet scan`). This is intentional — AI tool discovery is a different concern with its own model, reporters, and future policy layer.

```
vet
├── scan              # SCA: package vulnerability/malware analysis (existing)
├── query             # offline SCA analysis from JSON dumps (existing)
├── inspect           # deep package inspection (existing)
├── ai                # NEW: AI tooling namespace
│   └── discover      # discover AI tools, MCP servers, agents
├── agent             # AI agent execution (existing)
├── cloud             # SafeDep Cloud (existing)
├── server            # MCP server (existing)
└── ...
```

### `vet ai discover` — Primary Command

```
vet ai discover [flags]
```

**Purpose:** Discover AI coding agents, MCP servers, and AI tools configured on the local system and/or within a project.

### Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--scope` | | `""` (both) | Limit scope: `system`, `project`, or empty for both |
| `--project-dir` | `-D` | cwd | Project root for project-level discovery |
| `--report-json` | | `""` | Write JSON inventory to file |
| `--report-markdown` | | `""` | Write Markdown report to file |
| `--silent` | `-s` | `false` | Suppress default summary output |

### Default Output (Summary Table)

When no `--report-*` flags are set, `vet ai discover` prints a styled summary table to stderr (matching `vet scan`'s summary reporter pattern):

```
$ vet ai discover

Discovered 5 AI tools across 2 hosts

 TYPE         | NAME        | HOST        | SCOPE   | DETAIL
 mcp_server   | safedep     | claude_code | project | stdio: npx @safedep/mcp
 mcp_server   | postgres    | claude_code | project | stdio: npx @mcp/postgres
 mcp_server   | database    | cursor      | system  | stdio: node db-server.js
 coding_agent | Claude Code | claude_code | system  | ~/.claude/settings.json
 coding_agent | Cursor      | cursor      | system  | ~/.cursor/mcp.json
```

### Scope Filtering

```bash
# All tools (system + project-level from cwd):
vet ai discover

# System-level only (global configs in ~):
vet ai discover --scope system

# Project-level only (from cwd):
vet ai discover --scope project

# Project-level for a specific repo:
vet ai discover --scope project --project-dir /path/to/repo
```

When `--scope` is empty (default), both system and project discovery run. `--project-dir` defaults to the current working directory, consistent with `vet scan -D`.

### Report Formats

**JSON** (`--report-json`): Full machine-readable inventory for CI/CD integration, SIEM ingestion, or programmatic analysis.

```bash
vet ai discover --report-json ai-inventory.json
```

Output follows the `AIToolInventory` schema:

```json
{
  "tools": [
    {
      "name": "safedep",
      "type": "mcp_server",
      "scope": "project",
      "host": "claude_code",
      "config_path": "/Users/dev/project/.mcp.json",
      "mcp_server": {
        "transport": "stdio",
        "command": "npx",
        "args": ["-y", "@safedep/mcp"],
        "env_var_names": ["SAFEDEP_API_KEY"]
      },
      "metadata": {}
    }
  ]
}
```

**Markdown** (`--report-markdown`): Human-readable report for documentation, PRs, or audit artifacts.

### Implementation: `cmd/ai/`

```
cmd/ai/
├── main.go           # NewAICommand() → `vet ai` parent
└── discover.go       # `vet ai discover` subcommand
```

**`cmd/ai/main.go`:**

```go
package ai

import "github.com/spf13/cobra"

func NewAICommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "ai",
        Short: "AI tool discovery and analysis",
        RunE: func(cmd *cobra.Command, args []string) error {
            return cmd.Help()
        },
    }

    cmd.AddCommand(newDiscoverCommand())
    return cmd
}
```

**`cmd/ai/discover.go`** — Core flow:

```go
func newDiscoverCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "discover",
        Short: "Discover AI tools, MCP servers, and coding agents",
        RunE: func(cmd *cobra.Command, args []string) error {
            return runDiscover()
        },
    }

    // Register flags: --scope, --project-dir, --report-json, etc.
    return cmd
}

func runDiscover() error {
    // 1. Build DiscoveryConfig from flags
    config := aitool.DiscoveryConfig{
        HomeDir:    "", // use default
        ProjectDir: projectDir,
    }

    // 2. Get registry
    registry := aitool.DefaultRegistry()

    // 3. Collect results
    inventory := &aitool.AIToolInventory{}
    err := registry.Discover(config, func(tool *aitool.AITool) error {
        // Apply scope filter if set
        if scopeFilter != "" && string(tool.Scope) != scopeFilter {
            return nil
        }
        inventory.Add(tool)
        return nil
    })
    if err != nil {
        return err
    }

    // 4. Print default summary table (unless --silent)
    if !silent {
        printSummaryTable(inventory)
    }

    // 5. Run reporters
    return runReporters(inventory)
}
```

### Registration in `main.go`

```go
// main.go
import "github.com/safedep/vet/cmd/ai"

cmd.AddCommand(ai.NewAICommand())
```

### CI/CD Usage Examples

```bash
# Inventory check in CI — fail if any MCP servers found in project
vet ai discover --scope project --report-json /dev/stdout | \
  jq -e '.tools | map(select(.type == "mcp_server")) | length == 0'

# Generate audit artifact
vet ai discover --report-json ai-tools.json --report-markdown ai-tools.md

# Check only system-level tools
vet ai discover --scope system --report-json system-ai-tools.json
```

### Future Subcommands Under `vet ai`

| Command | Purpose | Status |
|---|---|---|
| `vet ai discover` | Discover AI tools on the system | **v1** |
| `vet ai audit` | Audit AI tool configs against policies | Future (after policy layer) |
| `vet ai report` | Generate reports from saved discovery data | Future (query-like offline mode) |

## MCP Server Config Parsing Rules

1. **Transport detection:** If `command` is present → `stdio`. If `url` is present → detect `sse` or `streamable_http` from URL pattern or explicit `type` field.
2. **Env var handling:** Extract key names from `env` map. **Never** store or log values.
3. **Disabled servers:** Some configs use `"disabled": true` — capture in `Enabled` field.
4. **Unknown fields:** Log at debug level and discard. Do not preserve raw config data — it may contain secrets. If a field is important enough to capture, add a typed field or use `Metadata` with a safe value (never raw content).

## Testing Strategy

1. **Unit tests per discoverer** — Use fixture config files in `pkg/aitool/fixtures/`. Override `HomeDir` and `ProjectDir` in `DiscoveryConfig` to point at test fixtures.
2. **Test handler error propagation** — Verify enumeration stops on handler error.
3. **Test missing/malformed configs** — Discoverers should log warnings and continue, not fail hard on missing or unparseable files.
4. **Test registry** — Verify all registered discoverers are called, results are aggregated.

## Example Output

### Console Summary (default)

```
$ vet ai discover

Discovered 8 AI tools across 4 sources

 TYPE          | NAME              | HOST           | SCOPE   | DETAIL
 coding_agent  | Claude Code       | claude_code    | system  | ~/.claude/settings.json
 mcp_server    | safedep           | claude_code    | project | stdio: npx @safedep/mcp
 mcp_server    | postgres          | claude_code    | project | stdio: npx @mcp/postgres
 coding_agent  | Cursor            | cursor         | system  | ~/.cursor/mcp.json
 mcp_server    | database          | cursor         | system  | stdio: node db-server.js
 cli_tool      | Aider             | binary_probe   | system  | /usr/local/bin/aider v0.82.1
 ai_extension  | GitHub Copilot    | ide_extensions | system  | github.copilot v1.250.0
 ai_extension  | Cline             | ide_extensions | system  | saoudrizwan.claude-dev v3.14.0
```

### JSON Report (`--report-json`)

```json
{
  "tools": [
    {
      "id": "a1b2c3d4e5f6",
      "source_id": "f1e2d3c4b5a6",
      "name": "Claude Code",
      "type": "coding_agent",
      "scope": "system",
      "host": "claude_code",
      "config_path": "/Users/dev/.claude/settings.json",
      "agent": {
        "instruction_files": ["/Users/dev/project/CLAUDE.md"],
        "permission_mode": "allowedTools"
      },
      "metadata": {}
    },
    {
      "id": "b2c3d4e5f6a7",
      "source_id": "e2d3c4b5a6f1",
      "name": "safedep",
      "type": "mcp_server",
      "scope": "project",
      "host": "claude_code",
      "config_path": "/Users/dev/project/.mcp.json",
      "mcp_server": {
        "transport": "stdio",
        "command": "npx",
        "args": ["-y", "@safedep/mcp"],
        "env_var_names": ["SAFEDEP_API_KEY"]
      },
      "metadata": {}
    },
    {
      "id": "c3d4e5f6a7b8",
      "source_id": "d3c4b5a6f1e2",
      "name": "database",
      "type": "mcp_server",
      "scope": "system",
      "host": "cursor",
      "config_path": "/Users/dev/.cursor/mcp.json",
      "mcp_server": {
        "transport": "stdio",
        "command": "node",
        "args": ["/path/to/db-server.js"],
        "env_var_names": ["DB_CONNECTION_STRING"]
      },
      "metadata": {}
    },
    {
      "id": "d4e5f6a7b8c9",
      "source_id": "c4b5a6f1e2d3",
      "name": "Aider",
      "type": "cli_tool",
      "scope": "system",
      "host": "binary_probe",
      "config_path": "/usr/local/bin/aider",
      "metadata": {
        "binary.version": "0.82.1",
        "binary.path": "/usr/local/bin/aider"
      }
    },
    {
      "id": "e5f6a7b8c9d0",
      "source_id": "b5a6f1e2d3c4",
      "name": "GitHub Copilot",
      "type": "ai_extension",
      "scope": "system",
      "host": "ide_extensions",
      "config_path": "/Users/dev/.vscode/extensions/extensions.json",
      "metadata": {
        "extension.id": "github.copilot",
        "extension.version": "1.250.0",
        "extension.ecosystem": "VSCodeExtensions"
      }
    }
  ]
}
```

## Future Roadmap

### v2: Analysis & Policy Layer

Build a CEL-based policy evaluator for AI tools following the `pkg/analyzer/filterv2/` architecture:

1. **Define protobuf schema** for AI tool policy input (`safedep.messages.policy.v1.AIToolInput`)
2. **Implement `AIToolEvaluator`** mirroring `filterv2.Evaluator` — compiles rules, evaluates against discovered tools
3. **Ship default policy suites** for common risk categories (overprivileged MCP, sensitive data exposure, unvetted packages, permissive agent configs)
4. **Integrate with `pkg/analyzer/`** so `vet scan` can evaluate AI tool policies alongside package policies
5. **Add `vet discover ai-tools --filter`** flag for CEL-based filtering on the CLI

### v3: Supply Chain Risk for MCP Packages

1. **Package extraction bridge** — Parse MCP server commands to extract installable package references (`npx @foo/bar` → `npm:@foo/bar@latest`, `uvx some-server` → `pypi:some-server`)
2. **Feed extracted packages into existing enrichment pipeline** — Vulnerability, malware, and scorecard analysis via `pkg/scanner/enrich_*.go`
3. **Unified reporting** — MCP server inventory + underlying package risk in a single report

### v4: Extended Detection

1. **Runtime detection** — Detect running MCP server processes (via `ps`) in addition to static config file parsing
2. **Instruction file analysis** — Parse CLAUDE.md / .cursorrules for risky patterns (e.g., instructions to disable security checks, broad file access grants)
3. **Cross-platform paths** — Windows (`%APPDATA%`) and Linux (`~/.config/`) path resolution
4. **Trust scoring** — Composite risk score per AI tool based on permission breadth, env var exposure, network access, and package supply chain risk

### Open Questions

1. Should the protobuf schema for AI tool policy input live in the existing `safedep.messages.policy.v1` package or a new `aitool.v1`?
2. How should we handle MCP servers that are defined identically across multiple hosts (e.g., same server in both Claude Code and Cursor)?
3. Should discovered AI tools participate in the existing `pkg/reporter/sync.go` cloud sync flow?

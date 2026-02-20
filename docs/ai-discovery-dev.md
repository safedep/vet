# AI Tool Discovery: Developer Guide

This document covers the internal structure of `pkg/aitool` for contributors who need to add new applications, CLI tools, IDE extensions, or modify discovery behavior.

## Package layout

| File | Purpose |
|------|---------|
| `model.go` | Core types: `AITool`, `AIToolType`, `AIToolScope`, inventory helpers |
| `reader.go` | `AIToolReader` interface that all discoverers implement |
| `registry.go` | `Registry` that wires discoverers and runs discovery, `DiscoveryConfig` |
| `scope.go` | `DiscoveryScope` with prerequisite validation |
| `mcp_config.go` | Shared MCP config parsing used by config-based discoverers |
| `cli_common.go` | Shared CLI probe/verify pipeline used by CLI tool discoverers |
| `sanitize.go` | Argument redaction for secret patterns |
| `known_extensions.go` | Map of recognized AI IDE extension IDs |

## Curated maps

Several maps require manual updates when adding support for new tools.

### `knownScopes` in `scope.go`

Maps each `AIToolScope` to its `ScopeMetadata` (prerequisites like `RequiresHomeDir` or `RequiresProjectDir`). A new scope must be registered here or `NewDiscoveryScope` will reject it.

### `knownAIExtensions` in `known_extensions.go`

Maps lowercase VSIX extension IDs to display names. The IDE extension discoverer filters installed extensions against this map. To recognize a new AI extension, add its ID and display name here.

### `ideDirNames` in `ai_extension.go`

Maps IDE config directory names (e.g. `.vscode`, `.cursor`) to human readable IDE names. This is used to label which IDE an extension belongs to. Add an entry when supporting a new IDE distribution.

### `argSecretPatterns` in `sanitize.go`

List of CLI argument prefixes (e.g. `--token=`, `--api-key=`) that trigger value redaction. Add new patterns here if a tool uses a nonstandard secret flag.

### `DefaultRegistry()` in `registry.go`

Wires all built-in discoverers in a fixed order. Any new discoverer must be registered here.

## Adding a new config-based app discoverer

A config-based discoverer reads JSON configuration files from well-known filesystem paths. Examples: `claude_code.go`, `cursor.go`, `windsurf.go`.

1. Create a new file (e.g. `newapp.go`) with a struct implementing `AIToolReader`.
2. Define an app constant (e.g. `const newappApp = "newapp"`).
3. In the factory function, resolve `HomeDir` from config (falling back to `os.UserHomeDir()`).
4. In `EnumTools`, gate system work behind `config.ScopeEnabled(AIToolScopeSystem)` and project work behind `config.ScopeEnabled(AIToolScopeProject)`.
5. Use `parseMCPAppConfig` and `emitMCPServers` from `mcp_config.go` if the app stores MCP servers in the standard `{"mcpServers": {...}}` JSON format.
6. Register the factory in `DefaultRegistry()`.
7. Add test fixtures under `fixtures/` and write tests following the pattern in existing `*_test.go` files.

## Adding a new CLI tool discoverer

A CLI tool discoverer searches `$PATH` for a binary, executes it with a version flag, and verifies the output matches a known pattern.

1. Create a new file (e.g. `newtool.go`) with a struct implementing `CLIToolVerifier`.
2. Implement `BinaryNames()` (candidate names to search), `VerifyArgs()` (flags to run), `VerifyOutput()` (regex to extract version), `DisplayName()`, and `App()`.
3. Create a factory function that returns `&cliToolDiscoverer{verifier: &newVerifier{}, config: config}`.
4. Register in `DefaultRegistry()`.
5. Add a test case to `TestCLIVerifiers_VerifyOutput` in `cli_common_test.go`.

## Adding a new IDE extension

Add a single entry to `knownAIExtensions` in `known_extensions.go`. The key must be the lowercase VSIX extension ID (e.g. `publisher.extension-name`). No other code changes are needed.

If the extension ships through a new IDE distribution not yet listed in `ideDirNames`, add the directory name mapping there as well.

## Scope rules

The `scope` field on emitted `AITool` entries must reflect where the configuration file physically lives, not which project it relates to.

- Files under `~/.<app>/` or similar user-global directories are `system` scoped.
- Files inside a project repository (e.g. `.mcp.json`, `.cursorrules`) are `project` scoped.

For example, `~/.claude/projects/*/settings.json` lives inside the system-level `~/.claude/` directory, so tools discovered from it are `system` scoped even though the directory name contains "projects".

## Shared MCP config parsing

`mcp_config.go` provides types and helpers shared across apps that use the common `{"mcpServers": {...}}` JSON format:

- `mcpServerEntry` represents a single server entry. It handles both `url` and `serverUrl` keys (Windsurf uses `serverUrl`). The `resolvedURL()` method normalizes this.
- `mcpAppConfig` represents the top-level JSON structure. Extra fields like `permissions` and `model` are used only by Claude Code; other apps ignore them.
- `parseMCPAppConfig(path)` reads and parses the file, logging a warning on parse errors.
- `emitMCPServers(cfg, path, scope, app, handler)` iterates servers in deterministic order and emits `AITool` entries with sanitized args and env var names (values are never captured).
- `detectTransport(entry)` infers the MCP transport from an explicit `type` field or falls back to heuristics (command present means stdio, URL with `/sse` means SSE, other URLs mean streamable HTTP).

## Security invariants

- Environment variable and header **values** are never stored. Only key names are recorded.
- CLI arguments matching patterns in `argSecretPatterns` are redacted by `SanitizeArgs`.
- No network calls are made during discovery. All data comes from local filesystem and `$PATH`.

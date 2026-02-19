# AI Tool Discovery

The `vet ai discover` command scans the local system and project directory to build an inventory of AI tool **usage signals**, including coding agents, MCP servers, CLI tools, IDE extensions, and project configuration files. It is useful for auditing what AI tooling is active across a development environment.

## What it discovers

The command does **not** discover unique tools. It discovers **usage signals**. The same tool (e.g. Claude Code) may appear multiple times because it can be configured at different scopes and in different config files. Each row in the output represents a distinct configuration entry, not a distinct binary.

For example, Claude Code might appear as:

| TYPE | NAME | SCOPE | Why |
|------|------|-------|-----|
| coding_agent | Claude Code | system | `~/.claude/settings.json` exists |
| project_config | Claude Code | project | Project has a `CLAUDE.md` |
| mcp_server | my-server | system | Configured in `~/.claude/settings.json` |
| mcp_server | my-server | project | Also configured in `.mcp.json` |

These are **not duplicates**. They represent separate configuration surfaces that may carry different settings, permissions, or MCP server wiring.

Note that `coding_agent` is only emitted when the tool is actually installed on the system (detected via system-level config or CLI binary). Project-level instruction and rule files such as `CLAUDE.md` or `.cursorrules` are reported as `project_config` instead, because these files are typically checked into version control and do not indicate that the current system has the tool.

## Key concepts

**Type** classifies the kind of AI tool usage detected:

- `coding_agent` is an AI coding assistant installed on the system, detected via system-level configuration directories.
- `mcp_server` is a Model Context Protocol server configured for a host application.
- `cli_tool` is a standalone AI CLI binary found on `$PATH`. Each candidate is executed with a version flag and the output is verified against known patterns.
- `ai_extension` is an AI-related IDE extension detected from installed extension manifests.
- `project_config` is an AI tool configuration or instruction file found in a project repository. It indicates the project is set up for a particular AI tool but does not prove the current developer uses it.

**Scope** indicates where the configuration lives:

- `system` refers to user-global config (e.g. `~/.claude/settings.json`, `~/.cursor/mcp.json`).
- `project` refers to repo-scoped config (e.g. `.mcp.json`, `.cursorrules`, `CLAUDE.md`).

**Host** is the application that owns the configuration (e.g. `claude_code`, `cursor`). Tools from the same host share an integration surface.

**MCP (Model Context Protocol)** is a protocol that lets coding agents call external tool servers. MCP servers can use `stdio`, `sse`, or `streamable_http` transports. The discovery reports the server name, transport, command or URL, and which environment variable names are referenced. Values are never captured.

## Usage

```bash
# Discover all AI tool usage signals
vet ai discover

# Only system-level signals
vet ai discover --scope system

# Only project-level signals for a specific directory
vet ai discover --scope project -D /path/to/repo

# Write a JSON inventory to a file
vet ai discover --report-json inventory.json

# JSON only, no table output
vet ai discover --report-json inventory.json --silent
```

## What is scanned

**Host configuration** is read from well-known system and project-level config paths for each supported host application. System-level configs (e.g. `~/.claude/settings.json`, `~/.cursor/mcp.json`) indicate the tool is installed. Project-level configs (e.g. `.mcp.json`, `.cursorrules`) indicate the project is set up for a tool.

**CLI binaries** are discovered by searching `$PATH` for known binary names. Each candidate is executed with a version flag and the output is verified against known patterns to confirm identity and extract the version number.

**IDE extensions** are discovered by reading extension manifests from supported IDE distributions and matching against a curated list of known AI extension identifiers.

## Security

The discovery process never captures environment variable or header values. Only key names are recorded. CLI arguments matching secret patterns (`--token=`, `--api-key=`, `--password=`, etc.) are redacted. No network calls are made. All discovery is based on local filesystem and `$PATH` inspection.

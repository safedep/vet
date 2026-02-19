# AI Tool Discovery

The `vet ai discover` command scans the local system and project directory to build an inventory of AI tool **usage signals**, including coding agents, MCP servers, CLI tools, and IDE extensions that are installed or configured. It is useful for auditing what AI tooling is active across a development environment.

## What it discovers

The command does **not** discover unique tools. It discovers **usage signals**. The same tool (e.g. Claude Code) may appear multiple times because it can be configured at different scopes and in different config files. Each row in the output represents a distinct configuration entry, not a distinct binary.

For example, Claude Code might appear as:

| TYPE | NAME | SCOPE | Why |
|------|------|-------|-----|
| coding_agent | Claude Code | system | `~/.claude/settings.json` exists |
| coding_agent | Claude Code | project | Project has a `CLAUDE.md` |
| mcp_server | my-server | system | Configured in `~/.claude/settings.json` |
| mcp_server | my-server | project | Also configured in `.mcp.json` |

These are **not duplicates**. They represent separate configuration surfaces that may carry different settings, permissions, or MCP server wiring.

## Key concepts

**Type** classifies the kind of AI tool usage detected:

- `coding_agent` is an AI coding assistant such as Claude Code or Cursor.
- `mcp_server` is a Model Context Protocol server configured for a host.
- `cli_tool` is a standalone AI CLI binary found on `$PATH` such as Aider, Amazon Q, or GitHub Copilot CLI.
- `ai_extension` is an AI-related IDE extension such as Copilot, Cody, or Cline.

**Scope** indicates where the configuration lives:

- `system` refers to user-global config (e.g. `~/.claude/settings.json`, `~/.cursor/mcp.json`).
- `project` refers to repo-scoped config (e.g. `.mcp.json`, `.cursorrules`, `CLAUDE.md`).

**Host** is the application that owns the configuration. Examples include `claude_code`, `cursor`, `aider`, and `ide_extensions`. Tools from the same host share an integration surface.

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

**Claude Code** reads `~/.claude/settings.json`, `~/.claude/projects/*/settings.json`, `{project}/.mcp.json`, `{project}/.claude/settings.json`, and `CLAUDE.md`.

**Cursor** reads `~/.cursor/mcp.json`, `{project}/.cursor/mcp.json`, `.cursorrules`, and `.cursor/rules/*`.

**CLI tools** are detected by looking for `claude`, `aider`, `gh` (with copilot extension), and `q` or `amazon-q` on `$PATH`.

**IDE extensions** are detected by reading extension manifests from VS Code, VSCodium, Cursor, and Windsurf and matching against known AI extension IDs such as GitHub Copilot, Cody, Cline, Continue, and Tabnine.

## Security

The discovery process never captures environment variable or header values. Only key names are recorded. CLI arguments matching secret patterns (`--token=`, `--api-key=`, `--password=`, etc.) are redacted. No network calls are made. All discovery is based on local filesystem and `$PATH` inspection.

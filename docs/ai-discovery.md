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

Note that `coding_agent` is emitted from system-level configuration (a config file or directory in the user's home), never from project files. Config can outlive an uninstalled agent, so each `coding_agent` also says how strong its install evidence is (see [Install evidence](#install-evidence)). Project-level instruction and rule files such as `CLAUDE.md` or `.cursorrules` are reported as `project_config` instead, because these files are typically checked into version control and do not indicate that the current system has the tool.

## Key concepts

**Type** classifies the kind of AI tool usage detected:

- `coding_agent` is an AI coding assistant configured on the system, detected via system-level configuration files or directories. Its `agent.installed` metadata says whether anything beyond that config shows it is still installed.
- `mcp_server` is a Model Context Protocol server configured for an application.
- `cli_tool` is a standalone AI CLI binary found on `$PATH`. Each candidate is executed with a version flag and the output is verified against known patterns.
- `ai_extension` is an AI-related IDE extension detected from installed extension manifests.
- `project_config` is an AI tool configuration or instruction file found in a project repository. It indicates the project is set up for a particular AI tool but does not prove the current developer uses it.

**Scope** indicates where the configuration lives:

- `system` refers to user-global config (e.g. `~/.claude/settings.json`, `~/.cursor/mcp.json`).
- `project` refers to repo-scoped config (e.g. `.mcp.json`, `.cursorrules`, `CLAUDE.md`).

**App** is the application that owns the configuration (e.g. `claude_code`, `cursor`). Tools from the same app share an integration surface.

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

**App configuration** is read from well-known system and project-level config paths for each supported application. System-level configs (e.g. `~/.claude/settings.json`, `~/.cursor/mcp.json`) indicate the tool is or was set up for the current user; they are not proof that it is still installed. Project-level configs (e.g. `.mcp.json`, `.cursorrules`) indicate the project is set up for a tool.

**CLI binaries** are discovered by searching `$PATH` for known binary names. Each candidate is executed with a version flag and the output is verified against known patterns to confirm identity and extract the version number.

**IDE extensions** are discovered by reading extension manifests from supported IDE distributions and matching against a curated list of known AI extension identifiers.

## Install evidence

Every `coding_agent` item carries two metadata keys, set after all discoverers have run:

- `agent.evidence`: comma-separated, sorted list of the signals found for the agent's app:
  - `config`: the system-level config the item was discovered from (always present).
  - `binary`: a `cli_tool` item for the same app whose binary was found on `$PATH` and verified.
  - `extension`: an installed IDE extension that belongs to the agent (e.g. Cline, Continue, Claude Code, Codex, Augment Code, Amazon Q).
  - `app_bundle`: one of the agent's documented install locations exists (e.g. `/Applications/Zed.app`, `%LOCALAPPDATA%\Programs\Microsoft VS Code`).
- `agent.installed`: `true` when the evidence includes anything other than `config`, otherwise `false`.

A `coding_agent` with `agent.installed=false` may be left over from an uninstalled agent, or the agent may be installed somewhere vet does not look (for example a CLI that is not on `$PATH`). The table output marks these rows with `(config only)` in the DETAIL column. The JSON report keeps the same shape and includes both keys in `metadata`.

## Supported tools

`~` is the user home directory (`%USERPROFILE%` on Windows). Paths are resolved
with the native OS path rules; discovery does not look across the WSL / Windows
filesystem boundary.

| Tool | App | System signals | Project signals | CLI binary |
|------|-----|----------------|-----------------|------------|
| Claude Code | `claude_code` | `~/.claude/settings.json`, `~/.claude/projects/*/settings.json`, `~/.claude.json`, plugin `.mcp.json` | `.mcp.json`, `.claude/settings.json`, `CLAUDE.md` | `claude` |
| Cursor | `cursor` | `~/.cursor/`, `~/.cursor/mcp.json` | `.cursor/mcp.json`, `.cursorrules`, `.cursor/rules/` | `cursor` |
| Windsurf | `windsurf` | `~/.codeium/windsurf/`, `mcp_config.json` | | `windsurf` |
| Antigravity | `antigravity` | `~/.antigravity/` (and XDG / `%APPDATA%` variants), `~/.gemini/antigravity/mcp_config.json` | | `antigravity` |
| VS Code (Copilot agent mode MCP) | `vscode` | `~/.vscode/`, `Code/User/mcp.json` | `.vscode/mcp.json` | `code` |
| OpenAI Codex | `codex` | `~/.codex/` (or `$CODEX_HOME`), `config.toml` `[mcp_servers]` | `.codex/config.toml` | `codex` |
| Gemini CLI | `gemini_cli` | `~/.gemini/settings.json` | `.gemini/settings.json`, `GEMINI.md` | `gemini` |
| GitHub Copilot CLI | `copilot_cli` | `~/.copilot/config.json` or `settings.json` (or `$COPILOT_HOME`), `mcp-config.json` | `.github/mcp.json` | `copilot` |
| GitHub Copilot CLI (gh extension) | `gh_copilot` | | | `gh extension list` |
| OpenCode | `opencode` | `~/.config/opencode/`, `opencode.json[c]` | `opencode.json[c]` | `opencode` |
| Qwen Code | `qwen_code` | `~/.qwen/`, `settings.json` | `.qwen/settings.json`, `QWEN.md` | `qwen` |
| Amp | `amp` | `~/.config/amp/`, `settings.json[c]` (`amp.mcpServers`) | `.amp/settings.json` | `amp` |
| Augment Code (Auggie) | `augment` | `~/.augment/`, `settings.json` | | `auggie` |
| Kiro | `kiro` | `~/.kiro/`, `settings/mcp.json` | `.kiro/settings/mcp.json`, `.kiro/steering/` | |
| Amazon Q Developer | `amazon_q` | `~/.aws/amazonq/`, `mcp.json` | `.amazonq/mcp.json` | `q`, `amazon-q` |
| JetBrains Junie | `junie` | `~/.junie/`, `mcp/mcp.json` | `.junie/mcp/mcp.json`, `.junie/guidelines.md` | |
| Goose | `goose` | `~/.config/goose/config.yaml` (`%APPDATA%\Block\goose\config` on Windows) | `.goosehints` | |
| Continue | `continue` | `~/.continue/`, `config.yaml` | `.continue/mcpServers/*.yaml` | |
| Zed | `zed` | `~/.config/zed/settings.json` (`%APPDATA%\Zed` on Windows), `context_servers` | | |
| Cline | `cline` | `~/.cline/`, VS Code `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `.clinerules` | |
| Roo Code | `roo_code` | VS Code `globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `.roo/mcp.json`, `.roorules`, `.roo/rules/` | |
| Aider | `aider` | | | `aider` |

Documented install locations used for `app_bundle` evidence:

| Tool | Locations |
|------|-----------|
| VS Code | `/Applications/Visual Studio Code.app`, `%LOCALAPPDATA%\Programs\Microsoft VS Code`, `%ProgramFiles%\Microsoft VS Code`, `/usr/share/code` |
| Windsurf | `/Applications/Windsurf.app` |
| Kiro | `/Applications/Kiro.app` |
| Zed | `/Applications/Zed.app`, `~/.local/zed.app` |
| Goose | `~/.local/bin/goose` |

AI IDE extensions recognised by ID: GitHub Copilot, GitHub Copilot Chat, Claude
Code, Codex, Gemini Code Assist, Cline, Roo Code, Kilo Code, Continue, Cody,
Tabnine, Amazon Q, Augment Code, Codeium and Supermaven.

## Security

The discovery process never captures environment variable or header values. Only key names are recorded. CLI arguments matching secret patterns (`--token=`, `--api-key=`, `--password=`, etc.) are redacted. No network calls are made. All discovery is based on local filesystem and `$PATH` inspection.

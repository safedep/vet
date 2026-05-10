# Design: Agent Skills Scanner

**Date:** 2026-05-08
**Status:** Approved

## Problem

`vet endpoint scan` (and its alias `vet ai discover`) discovers installed AI tools, MCP servers, coding agents, and extensions — but not **skills** (agent skill directories). Skills are a first-class artifact of AI coding agents (Claude Code, Cursor, Windsurf, etc.) and should be part of the endpoint inventory synced to SafeDep Cloud.

## Goal

Extend `vet endpoint scan` and `vet ai discover` to also discover and sync agent skills installed on the endpoint. No new commands, no new sinks, no new flags — pure extension of the existing inventory pipeline.

## Scope

- Scan project-local skill directories (e.g., `.claude/skills/`) and global skill directories (e.g., `~/.claude/skills/`)
- Each subdirectory = one skill; directory name = skill name
- Emit one `inventory.Item` per discovered skill directory
- Register as a new scanner kind `"agent-skill"` in the existing registry
- `vet ai discover` pins to both `ai-tool` and `agent-skill` kinds
- Cloud sync, local table, JSON report all work automatically through existing sinks

## Out of Scope

- Parsing skill file contents or frontmatter
- Detecting enabled/disabled state
- Any new CLI commands or flags

## Architecture

Pure extension following the `aitool` scanner pattern:

```
pkg/inventory/scanners/
├── scanners.go              ← add KindAgentSkill constant + descriptor
└── skills/
    ├── adapter.go           ← implements inventory.Scanner
    └── translate.go         ← skill discovery result → *inventory.Item
```

`cmd/endpoint/scan.go`: update `RunAITool` to pin `[]string{KindAITool, KindAgentSkill}`.

No changes to orchestrator, sinks, or any other command.

## Agent Registry

Each agent entry encodes the project-local path (relative to `cfg.ProjectDir`) and the global path (relative to `cfg.HomeDir`). Both paths are checked when the corresponding scope is enabled.

Supported agents (from the canonical table):

| Agent | Kind Flag | Project Path | Global Path |
|---|---|---|---|
| Amp, Kimi CLI, Replit, Universal | `amp`, `kimi-cli`, `replit`, `universal` | `.agents/skills/` | `~/.config/agents/skills/` |
| Antigravity | `antigravity` | `.agents/skills/` | `~/.gemini/antigravity/skills/` |
| Augment | `augment` | `.augment/skills/` | `~/.augment/skills/` |
| IBM Bob | `bob` | `.bob/skills/` | `~/.bob/skills/` |
| Claude Code | `claude-code` | `.claude/skills/` | `~/.claude/skills/` |
| OpenClaw | `openclaw` | `skills/` | `~/.openclaw/skills/` |
| Cline, Warp | `cline`, `warp` | `.agents/skills/` | `~/.agents/skills/` |
| CodeBuddy | `codebuddy` | `.codebuddy/skills/` | `~/.codebuddy/skills/` |
| Codex | `codex` | `.agents/skills/` | `~/.codex/skills/` |
| Command Code | `command-code` | `.commandcode/skills/` | `~/.commandcode/skills/` |
| Continue | `continue` | `.continue/skills/` | `~/.continue/skills/` |
| Cortex Code | `cortex` | `.cortex/skills/` | `~/.snowflake/cortex/skills/` |
| Crush | `crush` | `.crush/skills/` | `~/.config/crush/skills/` |
| Cursor | `cursor` | `.agents/skills/` | `~/.cursor/skills/` |
| Deep Agents | `deepagents` | `.agents/skills/` | `~/.deepagents/agent/skills/` |
| Droid | `droid` | `.factory/skills/` | `~/.factory/skills/` |
| Firebender | `firebender` | `.agents/skills/` | `~/.firebender/skills/` |
| Gemini CLI | `gemini-cli` | `.agents/skills/` | `~/.gemini/skills/` |
| GitHub Copilot | `github-copilot` | `.agents/skills/` | `~/.copilot/skills/` |
| Goose | `goose` | `.goose/skills/` | `~/.config/goose/skills/` |
| Junie | `junie` | `.junie/skills/` | `~/.junie/skills/` |
| iFlow CLI | `iflow-cli` | `.iflow/skills/` | `~/.iflow/skills/` |
| Kilo Code | `kilo` | `.kilocode/skills/` | `~/.kilocode/skills/` |
| Kiro CLI | `kiro-cli` | `.kiro/skills/` | `~/.kiro/skills/` |
| Kode | `kode` | `.kode/skills/` | `~/.kode/skills/` |
| MCPJam | `mcpjam` | `.mcpjam/skills/` | `~/.mcpjam/skills/` |
| Mistral Vibe | `mistral-vibe` | `.vibe/skills/` | `~/.vibe/skills/` |
| Mux | `mux` | `.mux/skills/` | `~/.mux/skills/` |
| OpenCode | `opencode` | `.agents/skills/` | `~/.config/opencode/skills/` |
| OpenHands | `openhands` | `.openhands/skills/` | `~/.openhands/skills/` |
| Pi | `pi` | `.pi/skills/` | `~/.pi/agent/skills/` |
| Qoder | `qoder` | `.qoder/skills/` | `~/.qoder/skills/` |
| Qwen Code | `qwen-code` | `.qwen/skills/` | `~/.qwen/skills/` |
| Roo Code | `roo` | `.roo/skills/` | `~/.roo/skills/` |
| Trae | `trae` | `.trae/skills/` | `~/.trae/skills/` |
| Trae CN | `trae-cn` | `.trae/skills/` | `~/.trae-cn/skills/` |
| Windsurf | `windsurf` | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` |
| Zencoder | `zencoder` | `.zencoder/skills/` | `~/.zencoder/skills/` |
| Neovate | `neovate` | `.neovate/skills/` | `~/.neovate/skills/` |
| Pochi | `pochi` | `.pochi/skills/` | `~/.pochi/skills/` |
| AdaL | `adal` | `.adal/skills/` | `~/.adal/skills/` |

Note: agents sharing the same project path (e.g., `amp`, `kimi-cli`, `replit`, `universal` all use `.agents/skills/`) are treated as separate entries — the `App` field on the emitted `Item` records which agent name the skill belongs to. Skills found in a shared path are emitted once per matching agent.

## Data Model

Each discovered skill directory produces one `*inventory.Item`:

```
Kind        = KindAgentSkill (9)
Name        = directory name (e.g. "yaad", "stop-slop")
App         = agent identifier (e.g. "claude-code")
Scope       = ScopeProject | ScopeSystem
ConfigPath  = absolute path to skill directory
ItemIdentity = FNV-64a( app + "/" + kind + "/" + scope + "/" + name + "/" + configPath )
Enabled     = nil
Metadata    = nil
```

## Scanner Logic

```
for each agentEntry in registry:
    for each (scope, dir) in [(ScopeProject, projectDir/agentEntry.ProjectPath),
                               (ScopeSystem,  homeDir/agentEntry.GlobalPath)]:
        if !cfg.ScopeEnabled(scope): continue
        if dir does not exist: continue
        for each entry in ReadDir(dir):
            if !entry.IsDir(): continue
            emit translate(agentEntry.App, scope, entry.Name(), dir/entry.Name())
```

## Item Identity

Follows the same FNV-64a scheme used by the aitool scanner:

```go
ItemIdentity = fmt.Sprintf("%x", fnv64a(app + "/" + kindStr + "/" + scopeStr + "/" + name + "/" + configPath))
```

## Changes Summary

| File | Change |
|---|---|
| `pkg/inventory/scanners/scanners.go` | Add `KindAgentSkill = "agent-skill"` constant; add descriptor to registry |
| `pkg/inventory/scanners/skills/adapter.go` | New — Scanner implementation |
| `pkg/inventory/scanners/skills/translate.go` | New — skill → Item translation |
| `cmd/endpoint/scan.go` | `RunAITool` pins `[]string{KindAITool, KindAgentSkill}` |

## Testing

- Unit tests in `pkg/inventory/scanners/skills/adapter_test.go` using a temp directory tree
- Unit tests in `pkg/inventory/scanners/skills/translate_test.go` for Item field correctness
- Existing scenario tests and orchestrator tests are unaffected

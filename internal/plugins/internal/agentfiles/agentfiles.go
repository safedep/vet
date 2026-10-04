// Package agentfiles names the files in a repository or a home directory
// that make an editor or a coding agent run commands or read instructions.
// The agentconfig extractor and the agentconfig control share it.
package agentfiles

import (
	"path"
	"strings"
)

// Type is the type of an agent or editor file.
type Type string

const (
	// EditorTasks is .vscode/tasks.json.
	EditorTasks Type = "editor-tasks"
	// ClaudeSettings is .claude/settings.json, with hooks.
	ClaudeSettings Type = "claude-settings"
	// DevContainer is devcontainer.json, with lifecycle commands.
	DevContainer Type = "devcontainer"
	// GitHook is a husky hook script.
	GitHook Type = "git-hook"
	// Lefthook is lefthook.yml.
	Lefthook Type = "lefthook"
	// MCPConfig is an MCP server config of an agent or an editor.
	MCPConfig Type = "mcp-config"
	// Instructions is an agent instruction file, such as CLAUDE.md.
	Instructions Type = "instructions"
)

// HomeFiles are the agent and editor files that a home directory can hold,
// by slash path relative to the home directory. Classify knows the type of
// each one.
var HomeFiles = []string{
	".vscode/tasks.json",
	".claude/settings.json",
	".claude/settings.local.json",
	".claude/CLAUDE.md",
	".mcp.json",
	".cursor/mcp.json",
	".vscode/mcp.json",
	".codeium/windsurf/mcp_config.json",
	".gemini/settings.json",
}

var instructionFiles = map[string]bool{
	"claude.md": true, "agents.md": true, "gemini.md": true,
	".cursorrules": true, ".windsurfrules": true, ".clinerules": true,
}

// Classify returns the type of a file, by its slash path relative to the
// target. ok is false for any other file.
func Classify(p string) (t Type, ok bool) {
	base := path.Base(p)
	dir := path.Base(path.Dir(p))
	lower := strings.ToLower(base)
	switch {
	case dir == ".vscode" && base == "tasks.json":
		return EditorTasks, true
	case dir == ".claude" && (base == "settings.json" || base == "settings.local.json"):
		return ClaudeSettings, true
	case dir == ".devcontainer" && base == "devcontainer.json", base == ".devcontainer.json":
		return DevContainer, true
	case dir == ".husky" && !strings.HasPrefix(base, "_") && !strings.HasPrefix(base, "."):
		return GitHook, true
	case base == "lefthook.yml" || base == "lefthook.yaml" || base == ".lefthook.yml" || base == ".lefthook.yaml":
		return Lefthook, true
	case base == ".mcp.json",
		base == "mcp.json" && (dir == ".cursor" || dir == ".vscode"),
		base == "mcp_config.json" && dir == "windsurf",
		base == "settings.json" && dir == ".gemini":
		return MCPConfig, true
	case instructionFiles[lower],
		base == "copilot-instructions.md" && dir == ".github",
		dir == "rules" && path.Base(path.Dir(path.Dir(p))) == ".cursor" && strings.HasSuffix(base, ".mdc"):
		return Instructions, true
	}
	return "", false
}

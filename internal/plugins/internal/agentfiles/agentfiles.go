// Package agentfiles names the files in a repository or a home directory
// that make an editor or a coding agent run commands or read instructions.
// The agentconfig extractor and the agentconfig control share it.
package agentfiles

import (
	"path"
	"slices"
	"strings"
)

// Type is the type of an agent or editor file.
type Type string

const (
	// EditorTasks is .vscode/tasks.json, .cursor/tasks.json or the user
	// tasks of an editor.
	EditorTasks Type = "editor-tasks"
	// EditorSettings is the settings.json of an editor, in .vscode or in
	// the user folder of the editor. A setting can make tasks run with no
	// prompt.
	EditorSettings Type = "editor-settings"
	// ClaudeSettings is .claude/settings.json, with hooks.
	ClaudeSettings Type = "claude-settings"
	// DevContainer is devcontainer.json, with lifecycle commands.
	DevContainer Type = "devcontainer"
	// GitHook is a husky hook script, or a hook of a .githooks folder that a
	// setup step points core.hooksPath at.
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
// each one. The user tasks of an editor run in every folder that it opens.
var HomeFiles = append([]string{
	".vscode/tasks.json",
	".claude/settings.json",
	".claude/settings.local.json",
	".claude/CLAUDE.md",
	".mcp.json",
	".cursor/mcp.json",
	".vscode/mcp.json",
	".codeium/windsurf/mcp_config.json",
	".gemini/settings.json",
}, userFiles()...)

// editorUserDirs are the folder names of the editors that keep user tasks
// and settings in <config dir>/<name>/User.
var editorUserDirs = []string{"Code", "Code - Insiders", "Cursor", "VSCodium", "Windsurf"}

// configDirs are the config folders of each OS, relative to the home
// directory: Linux, macOS and Windows.
var configDirs = []string{".config", "Library/Application Support", "AppData/Roaming"}

func userFiles() []string {
	var out []string
	for _, c := range configDirs {
		for _, e := range editorUserDirs {
			out = append(out, c+"/"+e+"/User/tasks.json", c+"/"+e+"/User/settings.json")
		}
	}
	return out
}

func isEditorUserDir(p string) bool {
	return path.Base(p) == "User" && slices.Contains(editorUserDirs, path.Base(path.Dir(p)))
}

// gitHooks are the hook names that git runs.
var gitHooks = map[string]bool{
	"applypatch-msg": true, "pre-applypatch": true, "post-applypatch": true,
	"pre-commit": true, "pre-merge-commit": true, "prepare-commit-msg": true,
	"commit-msg": true, "post-commit": true, "pre-rebase": true,
	"post-checkout": true, "post-merge": true, "pre-push": true,
	"post-rewrite": true, "reference-transaction": true, "push-to-checkout": true,
	"pre-auto-gc": true, "fsmonitor-watchman": true, "sendemail-validate": true,
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
	case base == "tasks.json" && (dir == ".vscode" || dir == ".cursor" || isEditorUserDir(path.Dir(p))):
		return EditorTasks, true
	case base == "settings.json" && (dir == ".vscode" || isEditorUserDir(path.Dir(p))):
		return EditorSettings, true
	case dir == ".claude" && (base == "settings.json" || base == "settings.local.json"):
		return ClaudeSettings, true
	case dir == ".devcontainer" && base == "devcontainer.json", base == ".devcontainer.json":
		return DevContainer, true
	case dir == ".husky" && !strings.HasPrefix(base, "_") && !strings.HasPrefix(base, "."),
		dir == ".githooks" && gitHooks[base]:
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

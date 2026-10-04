package agentfiles

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want Type
	}{
		{".vscode/tasks.json", EditorTasks},
		{"app/.vscode/tasks.json", EditorTasks},
		{".claude/settings.json", ClaudeSettings},
		{".claude/settings.local.json", ClaudeSettings},
		{".devcontainer/devcontainer.json", DevContainer},
		{".devcontainer.json", DevContainer},
		{".husky/pre-commit", GitHook},
		{"lefthook.yml", Lefthook},
		{".mcp.json", MCPConfig},
		{".cursor/mcp.json", MCPConfig},
		{".vscode/mcp.json", MCPConfig},
		{".codeium/windsurf/mcp_config.json", MCPConfig},
		{".gemini/settings.json", MCPConfig},
		{"CLAUDE.md", Instructions},
		{"docs/AGENTS.md", Instructions},
		{".cursorrules", Instructions},
		{".github/copilot-instructions.md", Instructions},
		{".cursor/rules/style.mdc", Instructions},
	}
	for _, tc := range cases {
		got, ok := Classify(tc.path)
		assert.True(t, ok, tc.path)
		assert.Equal(t, tc.want, got, tc.path)
	}
	for _, p := range []string{"tasks.json", "settings.json", ".husky/_/husky.sh", "README.md", "mcp.json", ".vscode/settings.json"} {
		_, ok := Classify(p)
		assert.False(t, ok, p)
	}
}

// TestHomeFilesClassify keeps one list of agent files: a home file that
// Classify does not know would reach no control.
func TestHomeFilesClassify(t *testing.T) {
	for _, f := range HomeFiles {
		_, ok := Classify(f)
		assert.True(t, ok, f)
	}
}

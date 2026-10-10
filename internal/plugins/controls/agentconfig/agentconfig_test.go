package agentconfig_test

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/controls/agentconfig"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

type want struct {
	id   string
	sev  finding.Severity
	line int
}

func TestAgentConfig(t *testing.T) {
	cases := []struct {
		path string
		want []want
	}{
		{".vscode/tasks.json", []want{
			{agentconfig.IDEditorTask, finding.SeverityMedium, 8},
			{agentconfig.IDEditorTask, finding.SeverityHigh, 13},
			{agentconfig.IDSuspiciousCommand, finding.SeverityCritical, 13},
		}},
		{".claude/settings.json", []want{
			{agentconfig.IDAgentHook, finding.SeverityMedium, 6},
			{agentconfig.IDAgentHook, finding.SeverityMedium, 11},
			{agentconfig.IDSuspiciousCommand, finding.SeverityCritical, 11},
		}},
		{".devcontainer/devcontainer.json", []want{
			{agentconfig.IDAgentHook, finding.SeverityMedium, 3},
			{agentconfig.IDAgentHook, finding.SeverityMedium, 6},
			{agentconfig.IDSuspiciousCommand, finding.SeverityCritical, 6},
			{agentconfig.IDAgentHook, finding.SeverityMedium, 5},
		}},
		{".husky/pre-commit", []want{{agentconfig.IDAgentHook, finding.SeverityMedium, 4}}},
		{"lefthook.yml", []want{{agentconfig.IDAgentHook, finding.SeverityMedium, 4}}},
		{".cursor/mcp.json", []want{
			{agentconfig.IDMCPServer, finding.SeverityMedium, 3},
			{agentconfig.IDMCPServer, finding.SeverityMedium, 4},
		}},
		{"CLAUDE.md", []want{{agentconfig.IDInstructionChange, finding.SeverityInfo, 1}}},
	}
	c, err := agentconfig.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	root := os.DirFS("testdata/repo")
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			m := &model.Manifest{ID: "m", Path: tc.path, Kind: model.ManifestKindAgentConfig, Root: root}
			fs := plugintest.TestControl(t, c, m, nil)
			var got []want
			for _, f := range fs {
				got = append(got, want{f.ControlID, f.Severity, f.Locus.StartLine})
				assert.Equal(t, finding.FamilyAgentConfig, f.Family)
			}
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestAgentConfigSkips(t *testing.T) {
	c, err := agentconfig.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	root := os.DirFS("testdata/repo")
	for _, m := range []*model.Manifest{
		{ID: "a", Path: ".vscode/tasks.json", Kind: model.ManifestKindWorkflow, Root: root},
		{ID: "b", Path: ".vscode/broken.json", Kind: model.ManifestKindAgentConfig, Root: root},
		{ID: "c", Path: ".vscode/tasks.json", Kind: model.ManifestKindAgentConfig},
	} {
		assert.Empty(t, plugintest.TestControl(t, c, m, nil), m.ID)
	}
	_, err = agentconfig.New(plugin.MapConfig(map[string]any{"x": 1}))
	assert.Error(t, err)
}

// testFile evaluates one file of a memory file system.
func testFile(t *testing.T, path, data string) []want {
	t.Helper()
	c, err := agentconfig.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	root := fstest.MapFS{path: {Data: []byte(data)}}
	m := &model.Manifest{ID: "m", Path: path, Kind: model.ManifestKindAgentConfig, Root: root}
	var got []want
	for _, f := range plugintest.TestControl(t, c, m, nil) {
		got = append(got, want{f.ControlID, f.Severity, f.Locus.StartLine})
	}
	return got
}

func TestAgentConfigUnreadable(t *testing.T) {
	unreadable := func(line int) []want {
		return []want{{agentconfig.IDUnreadable, finding.SeverityHigh, line}}
	}
	cases := []struct {
		name, path, data string
		want             []want
	}{
		{"missing comma", ".vscode/tasks.json", "{\n\"version\": \"2.0.0\"\n\"tasks\": []}", unreadable(3)},
		{"unterminated comment holds no command", ".vscode/tasks.json", "{\"tasks\": []} /* x", nil},
		{"wrong type", ".vscode/tasks.json", `{"tasks": [{"label": 5}]}`, unreadable(1)},
		{"broken MCP config", ".cursor/mcp.json", `{"mcpServers": {`, unreadable(1)},
		{"broken lefthook", "lefthook.yml", "pre-commit:\n  commands: [", unreadable(1)},
		{"too large", ".vscode/tasks.json", `{"tasks": []}` + strings.Repeat(" ", 17<<20), unreadable(1)},
		{"trailing comma parses", ".vscode/tasks.json", `{"tasks": [],}`, nil},
		{"empty file", ".vscode/tasks.json", " \n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.want, testFile(t, tc.path, tc.data))
		})
	}
}

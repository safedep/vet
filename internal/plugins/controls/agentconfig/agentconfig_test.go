package agentconfig_test

import (
	"os"
	"testing"

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

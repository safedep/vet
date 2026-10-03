package workflow

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

type hit struct {
	control string
	line    int
	title   string
}

// hardening keeps the findings of the hardening controls in evaluate. The
// phase 1 tests leave them out.
var hardening bool

func evaluate(t *testing.T, options plugin.MapConfig, file string, kind model.ManifestKind) []hit {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", file))
	require.NoError(t, err)
	c, err := New(options)
	require.NoError(t, err)
	p := ".github/workflows/" + file
	m := &model.Manifest{ID: "m1", Path: p, Kind: kind, Ecosystem: model.EcosystemGitHubActions, Root: fstest.MapFS{p: {Data: data}}}
	var out []hit
	for _, f := range plugintest.TestControl(t, c, m, nil) {
		if slices.Contains(hardeningIDs, f.ControlID) && !hardening {
			continue
		}
		require.NotNil(t, f.Locus)
		assert.Equal(t, p, f.Subject.File.Path)
		assert.NotEmpty(t, f.Locus.Snippet)
		require.NotNil(t, f.Remediation)
		out = append(out, hit{control: f.ControlID, line: f.Locus.StartLine, title: f.Title})
	}
	return out
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		kind    model.ManifestKind
		options plugin.MapConfig
		want    []hit
	}{
		{
			name: "dangerous trigger", file: "pwn.yml", kind: model.ManifestKindWorkflow,
			want: []hit{
				{IDDangerousTrigger, 11, "pull_request_target with a checkout of the pull request code in job build"},
				{IDDangerousTrigger, 20, "pull_request_target with a checkout of the pull request code in job cli"},
			},
		},
		{
			name: "template injection", file: "inject.yml", kind: model.ManifestKindWorkflow,
			want: []hit{
				{IDTemplateInjection, 9, "${{ github.event.issue.title }} in a script"},
				{IDTemplateInjection, 10, "${{ github.event.pull_request.title }} in a script"},
				{IDTemplateInjection, 10, "${{ github.event.commits.*.message }} in a script"},
				{IDTemplateInjection, 18, "${{ github.event.comment.body }} in a script"},
			},
		},
		{
			name: "unpinned action", file: "unpinned.yml", kind: model.ManifestKindWorkflow,
			want: []hit{
				{IDUnpinnedAction, 14, "other/repo/.github/workflows/build.yml@v1 is not pinned to a commit SHA"},
				{IDUnpinnedAction, 6, "actions/checkout@v4 is not pinned to a commit SHA"},
				{IDUnpinnedAction, 9, "my-org/tool@main is not pinned to a commit SHA"},
				{IDUnpinnedAction, 10, "docker://alpine:3.19 is not pinned to a commit SHA"},
				{IDUnpinnedAction, 12, "actions/checkout@v4 is not pinned to a commit SHA"},
			},
		},
		{
			name: "allow unpinned", file: "unpinned.yml", kind: model.ManifestKindWorkflow,
			options: plugin.MapConfig{"allow_unpinned": []any{"my-org/*", "other/repo", "docker://alpine"}},
			want: []hit{
				{IDUnpinnedAction, 6, "actions/checkout@v4 is not pinned to a commit SHA"},
				{IDUnpinnedAction, 12, "actions/checkout@v4 is not pinned to a commit SHA"},
			},
		},
		{
			name: "composite action", file: "action.yml", kind: model.ManifestKindWorkflow,
			want: []hit{
				{IDTemplateInjection, 6, "${{ github.head_ref }} in a script"},
				{IDUnpinnedAction, 5, "tj-actions/changed-files@v44 is not pinned to a commit SHA"},
			},
		},
		{name: "a template", file: "template.yml", kind: model.ManifestKindWorkflow},
		{name: "not a workflow", file: "unpinned.yml", kind: model.ManifestKindManifest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, evaluate(t, tc.options, tc.file, tc.kind))
		})
	}
}

func TestIdenticalSnippetsGetDistinctIDs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "unpinned.yml"))
	require.NoError(t, err)
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m1", Path: "ci.yml", Kind: model.ManifestKindWorkflow, Root: fstest.MapFS{"ci.yml": {Data: data}}}
	fs := plugintest.TestControl(t, c, m, nil)
	var checkout []string
	for _, f := range fs {
		if f.Locus.Snippet == "- uses: actions/checkout@v4" {
			checkout = append(checkout, f.ID)
		}
	}
	require.Len(t, checkout, 2)
	assert.NotEqual(t, checkout[0], checkout[1], "the occurrence index tells two identical lines apart")
}

func TestUntrusted(t *testing.T) {
	cases := []struct {
		expr string
		want []string
	}{
		{" github.event.issue.title ", []string{"github.event.issue.title"}},
		{"github.event['pull_request']['body']", []string{"github.event.pull_request.body"}},
		{"GitHub.Event.Issue.Title", []string{"github.event.issue.title"}},
		{"github.event.pages[2].page_name", []string{"github.event.pages.*.page_name"}},
		{"github.event.issue.number", nil},
		{"format('{0}', github.head_ref)", []string{"github.head_ref"}},
		{"github.event.issue.title_extra", nil},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			assert.Equal(t, tc.want, untrusted(tc.expr))
		})
	}
}

func TestPinned(t *testing.T) {
	cases := []struct {
		uses, name string
		ok         bool
	}{
		{"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "actions/checkout", true},
		{"actions/checkout@v4", "actions/checkout", false},
		{"actions/checkout", "actions/checkout", false},
		{"./local", "", true},
		{"docker://ghcr.io/o/i:1.0", "docker://ghcr.io/o/i", false},
		{"docker://localhost:5000/i", "docker://localhost:5000/i", false},
	}
	for _, tc := range cases {
		t.Run(tc.uses, func(t *testing.T) {
			name, ok := pinned(tc.uses)
			assert.Equal(t, tc.name, name)
			assert.Equal(t, tc.ok, ok)
		})
	}
}

func TestNewRejectsBadPattern(t *testing.T) {
	_, err := New(plugin.MapConfig{"allow_unpinned": []any{"["}})
	assert.Error(t, err)
}

func TestHardening(t *testing.T) {
	hardening = true
	t.Cleanup(func() { hardening = false })
	byID := func(hits []hit) map[string][]int {
		out := map[string][]int{}
		for _, h := range hits {
			if slices.Contains(hardeningIDs, h.control) {
				out[h.control] = append(out[h.control], h.line)
			}
		}
		return out
	}
	assert.Equal(t, map[string][]int{
		IDSelfHostedRunner:     {10},
		IDExcessivePermissions: {11},
		IDSpoofableBot:         {12},
		IDCachePoisoning:       {14},
		IDArtifactPoisoning:    {17},
		IDEnvInjection:         {19},
		IDSecretsExposure:      {20, 21, 24},
	}, sortLines(byID(evaluate(t, nil, "hardening.yml", model.ManifestKindWorkflow))))
	assert.Empty(t, byID(evaluate(t, nil, "hardened.yml", model.ManifestKindWorkflow)), "a workflow with read permissions and secrets in env is clean")
	assert.Equal(t, map[string][]int{IDExcessivePermissions: {1}}, byID(evaluate(t, nil, "unpinned.yml", model.ManifestKindWorkflow)), "a workflow with no permissions")
}

func sortLines(m map[string][]int) map[string][]int {
	for k := range m {
		slices.Sort(m[k])
	}
	return m
}

func TestElementNamesThePartAtFault(t *testing.T) {
	cases := []struct {
		file string
		want map[string][]string
	}{
		{file: "pwn.yml", want: map[string][]string{
			IDDangerousTrigger:     {"pull_request_target", "pull_request_target"},
			IDExcessivePermissions: {"permissions"},
		}},
		{file: "action.yml", want: map[string][]string{
			IDTemplateInjection: {"${{ github.head_ref }}"},
			IDUnpinnedAction:    {"tj-actions/changed-files@v44"},
		}},
		{file: "hardening.yml", want: map[string][]string{
			IDSelfHostedRunner:     {"runs-on: self-hosted"},
			IDExcessivePermissions: {"permissions: write-all"},
			IDSpoofableBot:         {"github.actor == 'dependabot[bot]'"},
			IDCachePoisoning:       {"actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af"},
			IDArtifactPoisoning:    {"actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"},
			IDEnvInjection:         {"GITHUB_ENV"},
			IDSecretsExposure:      {"secrets.NPM_TOKEN", "secrets: inherit", "toJSON(secrets)"},
			IDTemplateInjection:    {"${{ github.event.workflow_run.head_branch }}"},
		}},
		{file: "unpinned.yml", want: map[string][]string{
			IDExcessivePermissions: {"permissions"},
			IDUnpinnedAction:       {"actions/checkout@v4", "actions/checkout@v4", "docker://alpine:3.19", "my-org/tool@main", "other/repo/.github/workflows/build.yml@v1"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.file))
			require.NoError(t, err)
			c, err := New(plugin.MapConfig(nil))
			require.NoError(t, err)
			p := ".github/workflows/" + tc.file
			m := &model.Manifest{ID: "m1", Path: p, Kind: model.ManifestKindWorkflow, Root: fstest.MapFS{p: {Data: data}}}
			got := map[string][]string{}
			for _, f := range plugintest.TestControl(t, c, m, nil) {
				got[f.ControlID] = append(got[f.ControlID], f.Subject.File.Element)
			}
			for k := range got {
				slices.Sort(got[k])
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

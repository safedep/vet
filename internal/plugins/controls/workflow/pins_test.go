package workflow

import (
	"cmp"
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

const pinSHA = "11bd71901bbe5b1630ceea73d27597364c9af683"

func TestPins(t *testing.T) {
	cases := []struct {
		name    string
		action  *model.ActionCommit
		change  model.Change
		comment string
		want    []hit
		fix     string
	}{
		{
			name: "impostor", action: &model.ActionCommit{},
			want: []hit{{IDImpostorCommit, 6, "No branch or tag of actions/checkout contains commit 11bd71901bbe"}},
		},
		{name: "reachable with the tag of the comment", action: &model.ActionCommit{Reachable: true, Tags: []string{"v4", "v4.2.2"}}},
		{name: "a comment with no v prefix", action: &model.ActionCommit{Reachable: true, Tags: []string{"v4.2.2"}}, comment: "4.2.2"},
		{name: "no data", action: nil},
		{
			name: "the comment names another tag", action: &model.ActionCommit{Reachable: true, Tags: []string{"v4.1.0"}},
			want: []hit{{IDPinCommentMismatch, 6, "Tag v4.2.2 in the comment does not point to commit 11bd71901bbe of actions/checkout"}},
			fix:  "Pin the commit of v4.2.2, or change the comment to a tag of the pinned commit. Tag v4.1.0 points to the pinned commit.",
		},
		{
			name: "a moving major tag in the comment", action: &model.ActionCommit{Reachable: true, Ref: "main"},
			comment: "v4",
		},
		{name: "a pin that the pull request does not change", action: &model.ActionCommit{}, change: model.ChangeUnchanged},
		{
			name: "a pin that the pull request adds", action: &model.ActionCommit{}, change: model.ChangeAdded,
			want: []hit{{IDImpostorCommit, 6, "No branch or tag of actions/checkout contains commit 11bd71901bbe"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s # %s\n",
				pinSHA, cmp.Or(tc.comment, "v4.2.2"))
			p := &model.Package{ID: model.MustPackageVersion(model.EcosystemGitHubActions, "actions/checkout", pinSHA), Change: tc.change}
			p.Action = tc.action
			path := ".github/workflows/ci.yml"
			m := &model.Manifest{
				ID: "m1", Path: path, Kind: model.ManifestKindWorkflow, Ecosystem: model.EcosystemGitHubActions,
				Root: fstest.MapFS{path: {Data: []byte(data)}}, Packages: []*model.Package{p},
			}
			c, err := New(plugin.MapConfig(nil))
			require.NoError(t, err)
			var got []hit
			for _, f := range plugintest.TestControl(t, c, m, nil) {
				if f.ControlID == IDImpostorCommit || f.ControlID == IDPinCommentMismatch {
					require.NotNil(t, f.Remediation)
					if tc.fix != "" {
						assert.Equal(t, tc.fix, f.Remediation.Summary)
					}
					got = append(got, hit{control: f.ControlID, line: f.Locus.StartLine, title: f.Title})
				}
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCommentTag(t *testing.T) {
	cases := map[string]string{
		"- uses: a/b@sha # v4.2.0":         "v4.2.0",
		"- uses: a/b@sha # v4.2.0; setup":  "v4.2.0",
		"- uses: a/b@sha # tag=v1.2.3":     "v1.2.3",
		"- uses: a/b@sha # 1.2.3-rc.1":     "1.2.3-rc.1",
		"- uses: a/b@sha # v4":             "",
		"- uses: a/b@sha # pinned by hand": "",
		"- uses: a/b@sha":                  "",
	}
	for line, want := range cases {
		assert.Equal(t, want, commentTag(line), line)
	}
}

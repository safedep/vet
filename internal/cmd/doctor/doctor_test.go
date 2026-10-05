package doctor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/tui/checklist"
)

func TestSizeMessage(t *testing.T) {
	cases := []struct {
		name  string
		scans int
		used  int64
		limit string
		want  string
	}{
		{name: "limit", scans: 3, used: 12062720, limit: "2GB", want: "3 scans use 12.1 MB of the limit of 2GB"},
		{name: "no limit", scans: 0, used: 0, want: "0 scans use 0 B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sizeMessage(tc.scans, tc.used, tc.limit))
		})
	}
}

func TestStatusItem(t *testing.T) {
	for s, want := range map[Status]checklist.Status{Pass: checklist.Pass, Warn: checklist.Warn, Fail: checklist.Fail} {
		assert.Equal(t, want, s.item(), s)
	}
}

func TestGitHubTokenCheck(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want Check
	}{
		{"a token", map[string]string{"GH_TOKEN": "x"}, Check{ID: "github.token", Status: Pass, Message: "GitHub token from GH_TOKEN"}},
		{"no token", nil, Check{
			ID: "github.token", Status: Warn,
			Message: "no GitHub token. vet calls the GitHub API anonymously, with 60 calls an hour",
			Fix:     "Set GITHUB_TOKEN or run gh auth login.",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := github.EnvProvider{LookupEnv: func(k string) (string, bool) { v, ok := tc.vars[k]; return v, ok }}
			assert.Equal(t, tc.want, githubTokenCheck(context.Background(), tp))
		})
	}
}

package doctor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/tui/checklist"
	"github.com/safedep/vet/v2/report"
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
			Fix:     "Set GITHUB_TOKEN or run gh auth login to raise the limit.",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := github.EnvProvider{LookupEnv: func(k string) (string, bool) { v, ok := tc.vars[k]; return v, ok }}
			assert.Equal(t, tc.want, githubTokenCheck(context.Background(), tp))
		})
	}
}

func TestSymbolData(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	fresh := &report.SymbolBundle{ID: "f2e47dc1", SignedAt: now.Add(-24 * time.Hour), Records: 1220}
	stale := &report.SymbolBundle{ID: "f2e47dc1", SignedAt: now.Add(-10 * 24 * time.Hour), Records: 1220}
	function := func(b *report.SymbolBundle, s *report.ReachSources) *report.ReachInfo {
		return &report.ReachInfo{Level: report.ReachFunction, Status: report.ReachComputed, SymbolData: true, Symbols: b, Sources: s}
	}
	cases := []struct {
		name    string
		reach   *report.ReachInfo
		status  Status
		message string
	}{
		{name: "no reach", status: Pass, message: "the last scan computed no function reach"},
		{name: "import level", reach: &report.ReachInfo{Level: report.ReachImport, Status: report.ReachComputed}, status: Pass, message: "computed no function reach"},
		{name: "no bundle", reach: function(nil, nil), status: Warn, message: "had no symbol data"},
		{name: "no Go or Rust code", reach: &report.ReachInfo{Level: report.ReachFunction, Status: report.ReachComputed}, status: Pass, message: "needs no symbol data"},
		{name: "a fresh bundle", reach: function(fresh, &report.ReachSources{Found: 2}), status: Pass, message: "found the code of 2 of 2"},
		{name: "a stale bundle", reach: function(stale, nil), status: Warn, message: "more than 7 days ago"},
		{name: "a missing source", reach: function(fresh, &report.ReachSources{Found: 1, Missing: 2}), status: Warn, message: "found the code of 1 of 3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := symbolData(c.reach, now)
			assert.Equal(t, "reach.symbol-data", got.ID)
			assert.Equal(t, c.status, got.Status)
			assert.Contains(t, got.Message, c.message)
		})
	}
}

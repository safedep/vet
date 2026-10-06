package prcomment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

type fakeCommenter struct {
	existing *ci.Comment
	posted   []string
}

func (f *fakeCommenter) Find(context.Context, string) (*ci.Comment, error) { return f.existing, nil }

func (f *fakeCommenter) Upsert(_ context.Context, _ *ci.Comment, body string) (string, error) {
	f.posted = append(f.posted, body)
	return "https://github.com/acme/app/pull/1#issuecomment-1", nil
}

// prEnv is the environment of a GitHub Actions pull request run.
func prEnv(t *testing.T) func(string) string {
	t.Helper()
	event := filepath.Join(t.TempDir(), "event.json")
	require.NoError(t, os.WriteFile(event, []byte(`{"pull_request":{"number":1,"base":{"sha":"1111111"},"head":{"sha":"2222222222","repo":{"full_name":"acme/app"}}},"repository":{"full_name":"acme/app"}}`), 0o600))
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_SERVER_URL": "https://github.com",
		"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": event,
	}
	return func(k string) string { return env[k] }
}

func newPublisher(t *testing.T, create string, env func(string) string, cm *fakeCommenter) *Sink {
	t.Helper()
	s, err := New(plugin.MapConfig{"create": create})
	require.NoError(t, err)
	sink := s.(*Sink)
	sink.getenv = env
	sink.commenter = func(context.Context, ci.Context) (ci.Commenter, error) { return cm, nil }
	return sink
}

func TestPublish(t *testing.T) {
	clean := pullRequest(report.GatePass)
	clean.FindingList = nil
	noChange := pullRequest(report.GatePass)
	noChange.FindingList = nil
	for _, p := range noChange.ManifestList[0].Packages {
		p.Change = ""
	}
	cases := []struct {
		name     string
		create   string
		report   plugin.Report
		existing bool
		wantPost bool
	}{
		{name: "findings", create: CreateChanges, report: pullRequest(report.GateFail), wantPost: true},
		{name: "clean receipt", create: CreateChanges, report: clean, wantPost: true},
		{name: "no receipt with create findings", create: CreateFindings, report: clean},
		{name: "no change", create: CreateChanges, report: noChange},
		{name: "an existing comment is always edited", create: CreateFindings, report: clean, existing: true, wantPost: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cm := &fakeCommenter{}
			if tc.existing {
				cm.existing = &ci.Comment{ID: "1", Body: marker}
			}
			url, err := newPublisher(t, tc.create, prEnv(t), cm).Publish(context.Background(), tc.report)
			require.NoError(t, err)
			if !tc.wantPost {
				assert.Empty(t, cm.posted)
				assert.Empty(t, url)
				return
			}
			require.Len(t, cm.posted, 1)
			assert.NotEmpty(t, url)
		})
	}
}

func TestPublishReadsTheOldState(t *testing.T) {
	s := pullRequest(report.GatePass)
	fixed := s.FindingList[0].ID
	s.FindingList = s.FindingList[1:]
	block, ok := encodeState(state{Findings: []string{fixed}})
	require.True(t, ok)
	cm := &fakeCommenter{existing: &ci.Comment{ID: "1", Body: marker + "\nold\n" + block}}

	_, err := newPublisher(t, CreateChanges, prEnv(t), cm).Publish(context.Background(), s)
	require.NoError(t, err)
	require.Len(t, cm.posted, 1)
	assert.Contains(t, cm.posted[0], "**Since the last run:** 1 resolved")
	st, ok := decodeState(cm.posted[0])
	require.True(t, ok)
	assert.Equal(t, "2222222222", st.HeadSHA, "the state names the head of the pull request")
}

func TestPublishOutsideAPullRequest(t *testing.T) {
	cm := &fakeCommenter{}
	_, err := newPublisher(t, CreateChanges, func(string) string { return "" }, cm).Publish(context.Background(), pullRequest(report.GateFail))
	assert.ErrorIs(t, err, errNoChange)
	assert.Empty(t, cm.posted)
	assert.True(t, strings.Contains(err.Error(), "pull request"))
}

// readOnly is the GitHub adapter of a fork run: it reads, and it cannot
// write.
type readOnly struct{ fakeCommenter }

func (*readOnly) Upsert(context.Context, *ci.Comment, string) (string, error) {
	return "", ci.ErrNoWriteAccess
}

func TestPublishByProxy(t *testing.T) {
	forkEnv := func(t *testing.T, private bool) func(string) string {
		t.Helper()
		event := filepath.Join(t.TempDir(), "event.json")
		priv := "false"
		if private {
			priv = "true"
		}
		require.NoError(t, os.WriteFile(event, []byte(`{"pull_request":{"number":7,"base":{"sha":"1"},"head":{"sha":"3","repo":{"full_name":"someone/app"}}},"repository":{"full_name":"acme/app","private":`+priv+`}}`), 0o600))
		env := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": event}
		return func(k string) string { return env[k] }
	}
	cases := []struct {
		name     string
		private  bool
		noProxy  bool
		wantPost bool
		wantErr  string
	}{
		{name: "public fork", wantPost: true},
		{name: "private fork", private: true, wantErr: "private repository"},
		{name: "proxy off", noProxy: true, wantErr: "proxy is false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxied := &fakeCommenter{}
			sink := newPublisher(t, CreateChanges, forkEnv(t, tc.private), nil)
			sink.commenter = func(context.Context, ci.Context) (ci.Commenter, error) { return &readOnly{}, nil }
			sink.proxy = func(context.Context, ci.Context, ci.Commenter) (ci.Commenter, error) { return proxied, nil }
			if tc.noProxy {
				sink.proxy = nil
			}
			_, err := sink.Publish(context.Background(), pullRequest(report.GateFail))
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				assert.Empty(t, proxied.posted)
				return
			}
			require.NoError(t, err)
			require.Len(t, proxied.posted, 1)
			assert.Contains(t, proxied.posted[0], viaProxy)
		})
	}
}

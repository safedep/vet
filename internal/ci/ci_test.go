package ci

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func githubEnv(event, eventFile string) func(string) string {
	env := map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "acme/app",
		"GITHUB_SERVER_URL": "https://github.com",
		"GITHUB_API_URL":    "https://api.github.com",
		"GITHUB_RUN_ID":     "99",
		"GITHUB_EVENT_NAME": event,
		"GITHUB_EVENT_PATH": filepath.Join("testdata", eventFile),
	}
	return func(k string) string { return env[k] }
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name       string
		env        func(string) string
		wantOK     bool
		wantChange *Change
	}{
		{name: "no CI", env: func(string) string { return "" }},
		{
			name: "pull request", env: githubEnv("pull_request", "pull_request.json"), wantOK: true,
			wantChange: &Change{Number: 482, BaseSHA: "1111111111111111111111111111111111111111", HeadSHA: "2222222222222222222222222222222222222222", HeadRepository: "acme/app"},
		},
		{
			name: "fork", env: githubEnv("pull_request", "fork.json"), wantOK: true,
			wantChange: &Change{Number: 7, BaseSHA: "1111111111111111111111111111111111111111", HeadSHA: "3333333333333333333333333333333333333333", HeadRepository: "someone/app", Fork: true},
		},
		{
			name: "private fork with a deleted repository", env: githubEnv("pull_request", "private-fork.json"), wantOK: true,
			wantChange: &Change{Number: 8, BaseSHA: "1111111111111111111111111111111111111111", HeadSHA: "4444444444444444444444444444444444444444", Fork: true, Private: true},
		},
		{name: "push", env: githubEnv("push", "push.json"), wantOK: true},
		{name: "schedule", env: githubEnv("schedule", "push.json"), wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok, err := Detect(tc.env)
			require.NoError(t, err)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantChange, c.Change)
			if ok {
				assert.Equal(t, PlatformGitHub, c.Platform)
				assert.Equal(t, "https://github.com/acme/app/actions/runs/99", c.RunURL)
			}
		})
	}
}

func TestDetectBadEvent(t *testing.T) {
	_, ok, err := Detect(githubEnv("pull_request", "missing.json"))
	assert.True(t, ok)
	assert.ErrorContains(t, err, "read the GitHub event")
}

func TestSetOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(out, []byte("gate=pass\n"), 0o600))
	c := Context{Output: out}
	require.NoError(t, c.SetOutput("comment-url", "https://github.com/acme/app/pull/1#issuecomment-1"))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "gate=pass\ncomment-url=https://github.com/acme/app/pull/1#issuecomment-1\n", string(got))

	assert.ErrorContains(t, c.SetOutput("x", "a\nb=c"), "line break")
	assert.NoError(t, Context{}.SetOutput("x", "y"), "a run with no output file")
}

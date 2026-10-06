package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveCase is one case of action/testdata/resolve-cases.json. The jq
// resolver of the GitHub Action runs the same cases, so the two rules
// cannot drift.
type resolveCase struct {
	Name          string    `json:"name"`
	Releases      string    `json:"releases"`
	Channel       string    `json:"channel"`
	CooldownHours int       `json:"cooldown_hours"`
	MinVersion    string    `json:"min_version"`
	Now           time.Time `json:"now"`
	Want          string    `json:"want"`
}

func TestChoiceOnTheActionCases(t *testing.T) {
	dir := filepath.Join("..", "..", "action", "testdata")
	data, err := os.ReadFile(filepath.Join(dir, "resolve-cases.json"))
	require.NoError(t, err)
	var cases []resolveCase
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, tc.Releases))
			require.NoError(t, err)
			var releases []Release
			require.NoError(t, json.Unmarshal(raw, &releases))
			c := Choice{
				Major: "v2", Prerelease: tc.Channel == "prerelease", Immutable: true,
				Cooldown: time.Duration(tc.CooldownHours) * time.Hour, Minimum: tc.MinVersion, Now: tc.Now,
			}
			got, ok := c.Newest(releases)
			assert.Equal(t, tc.Want != "", ok)
			assert.Equal(t, tc.Want, got.Tag)
		})
	}
}

func TestListReleases(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/safedep/vet/releases", r.URL.Path, "vet never reads /releases/latest")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_, err := w.Write([]byte(`[{"tag_name":"v1.19.1","immutable":true}]`))
			assert.NoError(t, err)
			return
		}
		w.Header().Set("Link", `<`+srvURL+`/repos/safedep/vet/releases?per_page=100&page=2>; rel="next"`)
		_, err := w.Write([]byte(`[{"tag_name":"v2.0.0-alpha.1","prerelease":true,"immutable":true,"published_at":"2026-10-05T06:47:50Z"}]`))
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	client, err := NewClient(context.Background(), nil, srv.URL, srv.Client())
	require.NoError(t, err)

	got, err := ListReleases(context.Background(), client, "safedep", "vet")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "v2.0.0-alpha.1", got[0].Tag)
	assert.True(t, got[0].Immutable)
	assert.Equal(t, "v1.19.1", got[1].Tag)
}

func TestReleaseTag(t *testing.T) {
	cases := []struct {
		version string
		want    string
	}{
		{"2.0.0-alpha.20261005063951", "v2.0.0-alpha.20261005063951"},
		{"v2.1.0", "v2.1.0"},
		{"devel", ""},
		{"v2.0.0-20261005063951-0123456789ab", ""},
		{"2.1.0+dirty", ""},
	}
	for _, tc := range cases {
		got, ok := ReleaseTag(tc.version)
		assert.Equal(t, tc.want, got, tc.version)
		assert.Equal(t, tc.want != "", ok, tc.version)
	}
}

func TestChoiceOfEachMajor(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	releases := []Release{
		{Tag: "v7.0.0-beta.1", Prerelease: true, PublishedAt: old},
		{Tag: "v6.0.2", PublishedAt: old},
		{Tag: "v5.0.1", PublishedAt: old},
	}
	got, ok := Choice{Cooldown: 24 * time.Hour, Now: now}.Newest(releases)
	require.True(t, ok)
	assert.Equal(t, "v6.0.2", got.Tag)
}

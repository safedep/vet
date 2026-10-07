package githubci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/fix"
	"github.com/safedep/vet/v2/internal/github"
)

const (
	vetSHA      = "1111111111111111111111111111111111111111"
	checkoutSHA = "2222222222222222222222222222222222222222"
)

func TestWorkflow(t *testing.T) {
	data := Workflow(fix.Pin{SHA: vetSHA, Ref: "v2.0.0"}, fix.Pin{SHA: checkoutSHA, Ref: "v6.0.2"})
	var wf struct {
		On          map[string]any `yaml:"on"`
		Permissions map[string]any `yaml:"permissions"`
		Jobs        map[string]struct {
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &wf))
	assert.Equal(t, map[string]any{"pull_request": nil}, wf.On, "the docs never use pull_request_target")
	assert.Empty(t, wf.Permissions)
	job := wf.Jobs["vet"]
	assert.Equal(t, map[string]string{"contents": "read", "pull-requests": "write"}, job.Permissions)
	require.Len(t, job.Steps, 2)
	assert.Equal(t, "actions/checkout@"+checkoutSHA, job.Steps[0].Uses)
	assert.Equal(t, "false", job.Steps[0].With["persist-credentials"])
	assert.Equal(t, "safedep/vet@"+vetSHA, job.Steps[1].Uses)
	assert.Contains(t, string(data), "safedep/vet@"+vetSHA+" # v2.0.0\n")
}

// The action applies the policy file that vet ci init --policy writes, and
// its cooldown is the cooldown of vet ci update.
func TestDefaultsOfTheAction(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "action.yml"))
	require.NoError(t, err)
	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &action))
	assert.Equal(t, PolicyPath, action.Inputs["policy"].Default)
	assert.Equal(t, fmt.Sprint(CooldownHours), action.Inputs["release-cooldown"].Default)
}

// docs/github-action.md shows the workflow that vet ci init writes.
func TestDocsShowTheWorkflow(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "github-action.md"))
	require.NoError(t, err)
	wf := Workflow(fix.Pin{SHA: "<commit SHA>", Ref: "<release tag>"}, fix.Pin{SHA: "de0fac2e4500dabe0009e67214ff5f5447ce83dd", Ref: "v6.0.2"})
	assert.Contains(t, string(data), "```yaml\n"+string(wf)+"```")
}

func TestAddDependabot(t *testing.T) {
	entry := func(indent, eol string) string {
		return strings.ReplaceAll(indent+"- package-ecosystem: github-actions\n"+
			indent+"  directory: /\n"+
			indent+"  schedule:\n"+
			indent+"    interval: weekly\n"+
			indent+"  cooldown:\n"+
			indent+"    default-days: 1\n", "\n", eol)
	}
	gomod := "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n"
	cases := []struct {
		name   string
		old    *string
		want   string
		change DependabotChange
	}{
		{name: "no file", want: "version: 2\nupdates:\n" + entry("  ", "\n"), change: DependabotCreated},
		{name: "an entry at the end", old: &gomod, want: gomod + entry("  ", "\n"), change: DependabotAdded},
		{
			name:   "the indent of the file and no final line break",
			old:    ptr("version: 2\nupdates:\n    - package-ecosystem: npm\n      directory: /web\n      schedule: {interval: daily}"),
			want:   "version: 2\nupdates:\n    - package-ecosystem: npm\n      directory: /web\n      schedule: {interval: daily}\n" + entry("    ", "\n"),
			change: DependabotAdded,
		},
		{
			name:   "dashes at the column of the key",
			old:    ptr("version: 2\nupdates:\n- package-ecosystem: npm\n  directory: /\n  schedule:\n    interval: daily\n"),
			want:   "version: 2\nupdates:\n- package-ecosystem: npm\n  directory: /\n  schedule:\n    interval: daily\n" + entry("", "\n"),
			change: DependabotAdded,
		},
		{
			name:   "CRLF line ends",
			old:    ptr(strings.ReplaceAll(gomod, "\n", "\r\n")),
			want:   strings.ReplaceAll(gomod, "\n", "\r\n") + entry("  ", "\r\n"),
			change: DependabotAdded,
		},
		{
			name:   "an entry for the actions exists",
			old:    ptr("version: 2\nupdates:\n  - package-ecosystem: \"github-actions\"\n    directory: \"/\"\n    schedule: {interval: monthly}\n"),
			change: DependabotPresent,
		},
		{
			name:   "an entry for the actions in another directory",
			old:    ptr("version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /.github/workflows\n"),
			change: DependabotPresent,
		},
		{
			name:   "an entry for the actions with directories",
			old:    ptr("version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directories: [\"**/*\"]\n"),
			change: DependabotPresent,
		},
		{
			name:   "a block scalar with no final line break",
			old:    ptr("version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    commit-message:\n      prefix: |\n        deps"),
			change: DependabotManual,
		},
		{
			name:   "another key after updates",
			old:    ptr(gomod + "registries:\n  npm: {type: npm-registry, url: https://npm.example.com}\n"),
			change: DependabotManual,
		},
		{name: "a flow sequence", old: ptr("version: 2\nupdates: []\n"), change: DependabotManual},
		{name: "no updates", old: ptr("version: 2\n"), change: DependabotManual},
		{name: "not YAML", old: ptr("version: 2\nupdates: [\n"), change: DependabotManual},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var old []byte
			if tc.old != nil {
				old = []byte(*tc.old)
			}
			got, change := AddDependabot(old)
			assert.Equal(t, tc.change, change)
			switch tc.change {
			case DependabotCreated, DependabotAdded:
				assert.Equal(t, tc.want, string(got))
				again, change := AddDependabot(got)
				assert.Equal(t, DependabotPresent, change, "a second run adds no entry")
				assert.Equal(t, got, again)
			default:
				assert.Equal(t, old, got, "vet leaves the file as it is")
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestUsesRenovate(t *testing.T) {
	root := t.TempDir()
	found, err := UsesRenovate(root)
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, os.MkdirAll(filepath.Join(root, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".github", "renovate.json"), []byte("{}"), 0o644))
	found, err = UsesRenovate(root)
	require.NoError(t, err)
	assert.True(t, found)
}

func TestIsRepository(t *testing.T) {
	root := t.TempDir()
	assert.False(t, IsRepository(root))
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".github"), 0o755))
	assert.True(t, IsRepository(root))
}

// releasesServer serves the releases and the tag SHAs of two
// repositories.
func releasesServer(t *testing.T, releases map[string][]github.Release, shas map[string]string) *Pinner {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/repos/")
		if repo, ok := strings.CutSuffix(path, "/releases"); ok {
			if page := r.URL.Query().Get("page"); page != "" && page != "0" && page != "1" {
				_, err := w.Write([]byte("[]"))
				assert.NoError(t, err)
				return
			}
			assert.NoError(t, json.NewEncoder(w).Encode(releases[repo]))
			return
		}
		if sha, ok := shas[path]; ok {
			_, err := w.Write([]byte(sha))
			assert.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	client, err := github.NewClient(context.Background(), nil, srv.URL, srv.Client())
	require.NoError(t, err)
	return &Pinner{Client: client, Now: func() time.Time { return testNow }}
}

var testNow = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

func release(tag string, age time.Duration, prerelease, immutable bool) github.Release {
	return github.Release{Tag: tag, Prerelease: prerelease, Immutable: immutable, PublishedAt: testNow.Add(-age)}
}

func TestNewestVet(t *testing.T) {
	day := 24 * time.Hour
	alphas := []github.Release{
		release("v2.0.0-alpha.20261009000000", time.Hour, true, true),
		release("v2.0.0-alpha.20261008000000", 2*day, true, true),
		release("v2.0.0-alpha.20261007000000", 3*day, true, true),
		release("v1.19.1", 30*day, false, true),
	}
	cases := []struct {
		name     string
		releases []github.Release
		current  string
		want     string
	}{
		{name: "a pre-release while v2 has no stable release", releases: alphas, current: "v2.0.0-alpha.20261007000000", want: "v2.0.0-alpha.20261008000000"},
		{name: "a stable release wins over a newer pre-release", releases: append([]github.Release{release("v2.0.0", 2*day, false, true)}, alphas...), current: "v2.0.0-alpha.20261007000000", want: "v2.0.0"},
		{name: "a young stable release does not move a pin to a pre-release", releases: append([]github.Release{release("v2.0.0", time.Hour, false, true)}, alphas...), current: "v2.0.0-alpha.20261007000000"},
		{name: "a pin never moves to an older release", releases: alphas, current: "v2.0.0-alpha.20261009000000"},
		{name: "the newest release is the pin", releases: alphas, current: "v2.0.0-alpha.20261008000000"},
		{name: "a mutable release does not count", releases: []github.Release{release("v2.0.0-alpha.20261008000000", 2*day, true, false)}, current: "v2.0.0-alpha.20261007000000"},
	}
	shas := map[string]string{
		"safedep/vet/commits/v2.0.0-alpha.20261008000000": vetSHA,
		"safedep/vet/commits/v2.0.0":                      vetSHA,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := releasesServer(t, map[string][]github.Release{VetRepo: tc.releases}, shas).NewestVet(context.Background(), tc.current)
			require.NoError(t, err)
			assert.Equal(t, tc.want != "", ok)
			if tc.want != "" {
				assert.Equal(t, fix.Pin{SHA: vetSHA, Ref: tc.want}, got)
			}
		})
	}
}

func TestNewestCheckout(t *testing.T) {
	day := 24 * time.Hour
	releases := map[string][]github.Release{CheckoutRepo: {
		release("v7.0.0-beta.1", 3*day, true, false),
		release("v6.0.2", 3*day, false, false),
		release("v5.0.1", 90*day, false, false),
		release("v5.0.0", 120*day, false, false),
	}}
	shas := map[string]string{
		"actions/checkout/commits/v6.0.2": checkoutSHA,
		"actions/checkout/commits/v5.0.1": checkoutSHA,
	}
	p := releasesServer(t, releases, shas)
	ctx := context.Background()

	got, ok, err := p.NewestCheckout(ctx, "")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, fix.Pin{SHA: checkoutSHA, Ref: "v6.0.2"}, got, "the newest stable release of any major")

	got, ok, err = p.NewestCheckout(ctx, "v5.0.0")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "v5.0.1", got.Ref, "update stays in the major of the pin")

	young := map[string][]github.Release{CheckoutRepo: {release("v6.0.2", time.Hour, false, false)}}
	_, _, err = releasesServer(t, young, shas).NewestCheckout(ctx, "")
	require.ErrorIs(t, err, ErrNoRelease)
	assert.ErrorContains(t, err, "actions/checkout: no release passes the cooldown of 24 hours")
}

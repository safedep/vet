package githubci

import (
	"context"
	"encoding/json"
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

// The action applies the policy file that vet ci init --policy writes.
func TestPolicyPathIsTheDefaultOfTheAction(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "action.yml"))
	require.NoError(t, err)
	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &action))
	assert.Equal(t, PolicyPath, action.Inputs["policy"].Default)
}

func TestAddDependabot(t *testing.T) {
	entry := func(indent string) string {
		return indent + "- package-ecosystem: github-actions\n" +
			indent + "  directory: /\n" +
			indent + "  schedule:\n" +
			indent + "    interval: weekly\n" +
			indent + "  cooldown:\n" +
			indent + "    default-days: 1\n"
	}
	gomod := "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n"
	cases := []struct {
		name   string
		old    *string
		want   string
		change DependabotChange
	}{
		{name: "no file", want: "version: 2\nupdates:\n" + entry("  "), change: DependabotCreated},
		{name: "an entry at the end", old: &gomod, want: gomod + entry("  "), change: DependabotAdded},
		{
			name:   "the indent of the file",
			old:    ptr("version: 2\nupdates:\n    - package-ecosystem: npm\n      directory: /web\n      schedule: {interval: daily}"),
			want:   "version: 2\nupdates:\n    - package-ecosystem: npm\n      directory: /web\n      schedule: {interval: daily}\n" + entry("    "),
			change: DependabotAdded,
		},
		{
			name:   "dashes at the column of the key",
			old:    ptr("version: 2\nupdates:\n- package-ecosystem: npm\n  directory: /\n  schedule:\n    interval: daily\n"),
			want:   "version: 2\nupdates:\n- package-ecosystem: npm\n  directory: /\n  schedule:\n    interval: daily\n" + entry(""),
			change: DependabotAdded,
		},
		{
			name:   "an entry for the actions exists",
			old:    ptr("version: 2\nupdates:\n  - package-ecosystem: \"github-actions\"\n    directory: \"/\"\n    schedule: {interval: monthly}\n"),
			change: DependabotPresent,
		},
		{
			name:   "an entry for the actions with directories",
			old:    ptr("version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directories: [\"/\", \"/sub\"]\n"),
			change: DependabotPresent,
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
				cfg, ok := parseDependabot(got)
				require.True(t, ok)
				assert.True(t, cfg.hasActions())
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
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	return &Pinner{Client: client, Now: func() time.Time { return now }}
}

func TestPinner(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	release := func(tag string, age time.Duration, prerelease, immutable bool) github.Release {
		return github.Release{Tag: tag, Prerelease: prerelease, Immutable: immutable, PublishedAt: now.Add(-age)}
	}
	day := 24 * time.Hour
	alpha := map[string][]github.Release{
		VetRepo: {
			release("v2.0.0-alpha.20261009000000", time.Hour, true, true),
			release("v2.0.0-alpha.20261008000000", 2*day, true, true),
			release("v1.19.1", 30*day, false, true),
		},
		CheckoutRepo: {
			release("v7.0.0-beta.1", 3*day, true, false),
			release("v6.0.2", 3*day, false, false),
			release("v5.0.1", 90*day, false, false),
		},
	}
	shas := map[string]string{
		"safedep/vet/commits/v2.0.0-alpha.20261008000000": vetSHA,
		"safedep/vet/commits/v2.0.0":                      vetSHA,
		"actions/checkout/commits/v6.0.2":                 checkoutSHA,
	}
	p := releasesServer(t, alpha, shas)
	ctx := context.Background()

	got, err := p.NewestVet(ctx)
	require.NoError(t, err)
	assert.Equal(t, fix.Pin{SHA: vetSHA, Ref: "v2.0.0-alpha.20261008000000"}, got, "a pre-release while v2 has no stable release")

	got, err = p.NewestCheckout(ctx)
	require.NoError(t, err)
	assert.Equal(t, fix.Pin{SHA: checkoutSHA, Ref: "v6.0.2"}, got)

	got, err = p.Vet(ctx, "v2.0.0")
	require.NoError(t, err)
	assert.Equal(t, fix.Pin{SHA: vetSHA, Ref: "v2.0.0"}, got)

	ga := map[string][]github.Release{VetRepo: append([]github.Release{release("v2.0.0", 2*day, false, true)}, alpha[VetRepo]...)}
	got, err = releasesServer(t, ga, shas).NewestVet(ctx)
	require.NoError(t, err)
	assert.Equal(t, "v2.0.0", got.Ref, "a stable release wins over a newer pre-release")

	young := map[string][]github.Release{VetRepo: alpha[VetRepo][:1]}
	_, err = releasesServer(t, young, shas).NewestVet(ctx)
	assert.ErrorContains(t, err, "safedep/vet has no release that is older than 24h0m0s")
}

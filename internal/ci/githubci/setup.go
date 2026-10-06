package githubci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	gh "github.com/google/go-github/v70/github"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/fix"
	"github.com/safedep/vet/v2/internal/github"
)

// PolicyPath is the policy file that vet ci init --policy writes. The
// action reads it by default.
const PolicyPath = ".github/vet/policy.yml"

// The names of the vet workflow and of the Dependabot config. The first
// name is the one that vet writes. GitHub reads each of them.
var (
	WorkflowPaths   = []string{".github/workflows/vet.yml", ".github/workflows/vet.yaml"}
	DependabotPaths = []string{".github/dependabot.yml", ".github/dependabot.yaml"}
)

// The repositories of the actions that the workflow pins.
const (
	VetRepo      = "safedep/vet"
	CheckoutRepo = "actions/checkout"
)

// CooldownHours is the age in hours that a release needs before vet ci
// update pins it. It is the default of the cooldown input of the action.
const CooldownHours = 24

// IsRepository reports whether the repository at root is on GitHub: its
// origin remote is on github.com, or it has a .github directory.
func IsRepository(root string) bool {
	if github.OriginRepo(root) != "" {
		return true
	}
	info, err := os.Stat(filepath.Join(root, ".github"))
	return err == nil && info.IsDir()
}

// Workflow returns the vet workflow file with the two pins.
func Workflow(vet, checkout fix.Pin) []byte {
	return fmt.Appendf(nil, `name: vet
on:
  pull_request:
permissions: {}
concurrency:
  group: vet-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
jobs:
  vet:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: %s@%s # %s
        with:
          persist-credentials: false
      - uses: %s@%s # %s
`, CheckoutRepo, checkout.SHA, checkout.Ref, VetRepo, vet.SHA, vet.Ref)
}

// ErrNoRelease is the error of a repository with no release that the
// rule takes.
var ErrNoRelease = errors.New("no release passes")

// Pinner finds the pins of the workflow with the GitHub API.
type Pinner struct {
	Client *gh.Client
	Now    func() time.Time
}

// Vet returns the pin of the vet release tag.
func (p Pinner) Vet(ctx context.Context, tag string) (fix.Pin, error) {
	return p.pin(ctx, VetRepo, tag)
}

// NewestVet returns the pin of the newest immutable v2 release that is
// older than the cooldown and not older than current, or false when no
// such release is newer than current. It takes a stable release when v2
// has one, and a pre-release only while v2 has no stable release.
func (p Pinner) NewestVet(ctx context.Context, current string) (fix.Pin, bool, error) {
	releases, err := p.releases(ctx, VetRepo)
	if err != nil {
		return fix.Pin{}, false, err
	}
	c := github.Choice{Major: "v2", Immutable: true, Now: p.Now()}
	_, stable := c.Newest(releases)
	c.Prerelease = !stable
	c.Cooldown = CooldownHours * time.Hour
	c.Minimum = current
	return p.newer(ctx, VetRepo, c, releases, current)
}

// NewestCheckout returns the pin of the newest stable release of
// actions/checkout that is older than the cooldown. With a current tag,
// it stays in the major of current and returns false when no release is
// newer.
func (p Pinner) NewestCheckout(ctx context.Context, current string) (fix.Pin, bool, error) {
	releases, err := p.releases(ctx, CheckoutRepo)
	if err != nil {
		return fix.Pin{}, false, err
	}
	c := github.Choice{Cooldown: CooldownHours * time.Hour, Now: p.Now(), Minimum: current}
	if v := github.SemverOf(current); v != "" {
		c.Major = semver.Major(v)
	}
	return p.newer(ctx, CheckoutRepo, c, releases, current)
}

func (p Pinner) newer(ctx context.Context, repo string, c github.Choice, releases []github.Release, current string) (fix.Pin, bool, error) {
	r, ok := c.Newest(releases)
	switch {
	case !ok && current == "":
		return fix.Pin{}, false, fmt.Errorf("%s: %w the cooldown of %d hours", repo, ErrNoRelease, CooldownHours)
	case !ok || r.Tag == current:
		return fix.Pin{}, false, nil
	}
	pin, err := p.pin(ctx, repo, r.Tag)
	return pin, err == nil, err
}

func (p Pinner) releases(ctx context.Context, repo string) ([]github.Release, error) {
	owner, name, _ := strings.Cut(repo, "/")
	releases, err := github.ListReleases(ctx, p.Client, owner, name)
	if err != nil {
		return nil, fmt.Errorf("list the releases of %s: %w", repo, err)
	}
	return releases, nil
}

func (p Pinner) pin(ctx context.Context, repo, tag string) (fix.Pin, error) {
	owner, name, _ := strings.Cut(repo, "/")
	sha, err := fix.GitHubResolver{Client: p.Client}.ResolveSHA(ctx, owner, name, tag)
	if err != nil {
		return fix.Pin{}, err
	}
	return fix.Pin{SHA: sha, Ref: tag}, nil
}

// DependabotEntry is the entry that vet adds to the Dependabot config. It
// keeps the action pins up to date, one day after each release.
const DependabotEntry = `  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 1
`

// DependabotChange says what AddDependabot did.
type DependabotChange int

const (
	// DependabotCreated is a new config file.
	DependabotCreated DependabotChange = iota
	// DependabotAdded adds the entry at the end of the config.
	DependabotAdded
	// DependabotPresent leaves a config that has a github-actions entry.
	DependabotPresent
	// DependabotManual leaves a config that vet cannot extend with new
	// lines only. The user adds DependabotEntry.
	DependabotManual
)

// AddDependabot returns the Dependabot config with DependabotEntry. old is
// the config, or nil when the file does not exist. vet only adds lines at
// the end of the file. It checks that each value of the old config stays
// the same, so it never changes a setting of the user.
func AddDependabot(old []byte) ([]byte, DependabotChange) {
	if old == nil {
		return []byte("version: 2\nupdates:\n" + DependabotEntry), DependabotCreated
	}
	var before map[string]any
	if err := yaml.Unmarshal(old, &before); err != nil {
		return old, DependabotManual
	}
	updates, _ := before["updates"].([]any)
	for _, u := range updates {
		if m, ok := u.(map[string]any); ok && m["package-ecosystem"] == "github-actions" {
			return old, DependabotPresent
		}
	}
	dash, ok := lastBlockSequence(old, "updates")
	if !ok {
		return old, DependabotManual
	}
	eol := "\n"
	if bytes.Contains(old, []byte("\r\n")) {
		eol = "\r\n"
	}
	out := bytes.Clone(old)
	if !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, eol...)
	}
	for _, line := range strings.SplitAfter(DependabotEntry, "\n") {
		if line != "" {
			out = append(out, strings.Repeat(" ", dash)+strings.TrimSuffix(strings.TrimPrefix(line, "  "), "\n")+eol...)
		}
	}
	if !onlyAdds(before, out) {
		return old, DependabotManual
	}
	return out, DependabotAdded
}

// onlyAdds reports whether the config out holds each value of before, and
// the entry of vet as one more update at the end.
func onlyAdds(before map[string]any, out []byte) bool {
	var after, entry map[string]any
	var entries []any
	if yaml.Unmarshal(out, &after) != nil || yaml.Unmarshal([]byte(DependabotEntry), &entries) != nil || len(entries) != 1 {
		return false
	}
	entry, _ = entries[0].(map[string]any)
	updates, _ := before["updates"].([]any)
	want := map[string]any{}
	for k, v := range before {
		want[k] = v
	}
	want["updates"] = append(append([]any{}, updates...), entry)
	return reflect.DeepEqual(want, after)
}

// lastBlockSequence returns the column of the dashes of key when key is
// the last key of the top mapping and its value is a block sequence with
// at least one item. New items can then go at the end of the file.
func lastBlockSequence(data []byte, key string) (int, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) != 1 {
		return 0, false
	}
	top := doc.Content[0]
	n := len(top.Content)
	if top.Kind != yaml.MappingNode || n < 2 || top.Content[n-2].Value != key {
		return 0, false
	}
	seq := top.Content[n-1]
	if seq.Kind != yaml.SequenceNode || seq.Style&yaml.FlowStyle != 0 || len(seq.Content) == 0 {
		return 0, false
	}
	lines := strings.Split(string(data), "\n")
	first := seq.Content[0]
	if first.Line < 1 || first.Line > len(lines) {
		return 0, false
	}
	line := lines[first.Line-1]
	dash := strings.IndexByte(line, '-')
	if dash < 0 || strings.TrimSpace(line[:dash]) != "" {
		return 0, false
	}
	return dash, true
}

// renovateFiles are the config files of Renovate.
var renovateFiles = []string{
	"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".renovaterc.json5",
	".github/renovate.json", ".github/renovate.json5", ".gitlab/renovate.json", ".gitlab/renovate.json5",
}

// UsesRenovate reports whether the repository at root has a Renovate
// config.
func UsesRenovate(root string) (bool, error) {
	for _, name := range renovateFiles {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))
		switch {
		case err == nil:
			return true, nil
		case !errors.Is(err, os.ErrNotExist):
			return false, err
		}
	}
	return false, nil
}

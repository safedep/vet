package githubci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	gh "github.com/google/go-github/v70/github"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/fix"
	"github.com/safedep/vet/v2/internal/github"
)

// The files that vet ci init writes. The action reads PolicyPath by
// default.
const (
	WorkflowPath   = ".github/workflows/vet.yml"
	PolicyPath     = ".github/vet/policy.yml"
	DependabotPath = ".github/dependabot.yml"
)

// The repositories of the actions that the workflow pins.
const (
	VetRepo      = "safedep/vet"
	CheckoutRepo = "actions/checkout"
)

// Cooldown is the age that a release needs before vet ci update pins it.
const Cooldown = 24 * time.Hour

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
// older than the cooldown. It takes a stable release when one exists, and
// a pre-release only while v2 has no stable release.
func (p Pinner) NewestVet(ctx context.Context) (fix.Pin, error) {
	c := github.Choice{Major: "v2", Immutable: true, Cooldown: Cooldown, Now: p.Now()}
	return p.newest(ctx, VetRepo, c, true)
}

// NewestCheckout returns the pin of the newest stable release of
// actions/checkout that is older than the cooldown.
func (p Pinner) NewestCheckout(ctx context.Context) (fix.Pin, error) {
	return p.newest(ctx, CheckoutRepo, github.Choice{Cooldown: Cooldown, Now: p.Now()}, false)
}

func (p Pinner) newest(ctx context.Context, repo string, c github.Choice, prerelease bool) (fix.Pin, error) {
	owner, name, _ := strings.Cut(repo, "/")
	releases, err := github.ListReleases(ctx, p.Client, owner, name)
	if err != nil {
		return fix.Pin{}, fmt.Errorf("list the releases of %s: %w", repo, err)
	}
	r, ok := c.Newest(releases)
	if !ok && prerelease {
		c.Prerelease = true
		r, ok = c.Newest(releases)
	}
	if !ok {
		return fix.Pin{}, fmt.Errorf("%s has no release that is older than %s", repo, c.Cooldown)
	}
	return p.pin(ctx, repo, r.Tag)
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
	// DependabotPresent leaves a config that has a github-actions entry
	// for the root.
	DependabotPresent
	// DependabotManual leaves a config that vet cannot extend with new
	// lines only. The user adds DependabotEntry.
	DependabotManual
)

// AddDependabot returns the Dependabot config with DependabotEntry. old is
// the config, or nil when the file does not exist. vet only adds lines at
// the end of the file. It never changes a line of the user.
func AddDependabot(old []byte) ([]byte, DependabotChange) {
	if old == nil {
		return []byte("version: 2\nupdates:\n" + DependabotEntry), DependabotCreated
	}
	cfg, ok := parseDependabot(old)
	switch {
	case !ok:
		return old, DependabotManual
	case cfg.hasActions():
		return old, DependabotPresent
	}
	updates, ok := lastBlockSequence(old, "updates")
	if !ok {
		return old, DependabotManual
	}
	out := bytes.Clone(old)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	indent := strings.Repeat(" ", updates.dash)
	for _, line := range strings.SplitAfter(DependabotEntry, "\n") {
		if line != "" {
			out = append(out, indent+strings.TrimPrefix(line, "  ")...)
		}
	}
	added, ok := parseDependabot(out)
	if !ok || len(added.Updates) != len(cfg.Updates)+1 || !added.hasActions() {
		return old, DependabotManual
	}
	return out, DependabotAdded
}

type dependabot struct {
	Updates []struct {
		Ecosystem   string   `yaml:"package-ecosystem"`
		Directory   string   `yaml:"directory"`
		Directories []string `yaml:"directories"`
	} `yaml:"updates"`
}

func parseDependabot(data []byte) (dependabot, bool) {
	var cfg dependabot
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return dependabot{}, false
	}
	return cfg, true
}

func (d dependabot) hasActions() bool {
	for _, u := range d.Updates {
		if u.Ecosystem != "github-actions" {
			continue
		}
		if u.Directory == "/" || slices.Contains(u.Directories, "/") {
			return true
		}
	}
	return false
}

// blockSequence is a block sequence and the column of its dashes.
type blockSequence struct{ dash int }

// lastBlockSequence finds key when it is the last key of the top mapping
// and its value is a block sequence with at least one item. New items can
// then go at the end of the file.
func lastBlockSequence(data []byte, key string) (blockSequence, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) != 1 {
		return blockSequence{}, false
	}
	top := doc.Content[0]
	n := len(top.Content)
	if top.Kind != yaml.MappingNode || n < 2 || top.Content[n-2].Value != key {
		return blockSequence{}, false
	}
	seq := top.Content[n-1]
	if seq.Kind != yaml.SequenceNode || seq.Style&yaml.FlowStyle != 0 || len(seq.Content) == 0 {
		return blockSequence{}, false
	}
	lines := strings.Split(string(data), "\n")
	first := seq.Content[0]
	if first.Line < 1 || first.Line > len(lines) {
		return blockSequence{}, false
	}
	line := lines[first.Line-1]
	dash := strings.IndexByte(line, '-')
	if dash < 0 || strings.TrimSpace(line[:dash]) != "" {
		return blockSequence{}, false
	}
	return blockSequence{dash: dash}, true
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

// Package ci holds the "vet ci" commands. They write the files that run vet
// in the CI of a repository. They commit nothing.
package ci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/ci/githubci"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/diff"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/version"
)

// The error codes of the ci commands. A usage code exits 2, and
// CodeGitHub exits 3.
const (
	CodePlatform = "usage_ci_platform"
	CodeGitHub   = "ci_github"
)

// ciDocs is the page that shows how to run vet in another CI.
const ciDocs = "https://github.com/safedep/vet/blob/v2/docs/ci.md"

// New returns the "vet ci" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "ci",
		Short: "Set up vet in the CI of a repository",
		Long: `The ci commands write the files that run vet in the CI of a repository.
vet knows GitHub Actions. The commands write files and commit nothing.`,
	}
	c.AddCommand(newInit(a), newUpdate(a))
	return c
}

func newInit(a *app.App) *cobra.Command {
	var force, withPolicy, dryRun bool
	c := &cobra.Command{
		Use:   "init [DIR]",
		Short: "Add the vet workflow to a repository",
		Long: `Write .github/workflows/vet.yml, which runs the vet GitHub Action on each
pull request. vet pins the action to the commit of this vet release, and
actions/checkout to the commit of its newest release. A development build
of vet has no release to pin.

vet also adds a github-actions entry with a one day cooldown to the
Dependabot config, so Dependabot moves the pins. vet only adds lines at
the end of the file. When it cannot, it prints the entry for you to add.
A repository with a Renovate config gets no entry.

--policy also writes .github/vet/policy.yml with the starter rules of the
policy init command. --force replaces files that exist. --dry-run prints
the diff and writes nothing. DIR is the root of the repository. The
default is the current directory.`,
		Example: `  vet ci init --dry-run    # Show the files and write nothing
  vet ci init              # Add the workflow
  vet ci init --policy     # Add the workflow and a starter policy`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, err := openRepo(rootOf(args))
			if err != nil {
				return err
			}
			defer repo.close()
			tag, ok := github.ReleaseTag(version.Version())
			if !ok {
				return app.UsageError("vet ci init pins the action to this vet release, and this vet is a development build",
					"Install a release of vet, or copy the workflow from the docs page github-action.md of vet.")
			}

			wfPath, wf, err := repo.first(githubci.WorkflowPaths)
			if err != nil {
				return err
			}
			if wf != nil && !force {
				return app.UsageError(fmt.Sprintf("The workflow %s exists", wfPath),
					"Run vet ci update to move its pins, or pass --force to replace the file.")
			}
			var changes []change
			if withPolicy {
				old, err := repo.read(githubci.PolicyPath)
				switch {
				case err != nil:
					return err
				case old != nil && !force:
					tui.Info("vet keeps the policy file %s, because it exists", githubci.PolicyPath)
				default:
					changes = append(changes, change{path: githubci.PolicyPath, before: old, after: []byte(policy.Starter)})
				}
			}
			dependabot, err := dependabotChange(repo)
			if err != nil {
				return err
			}
			if dependabot != nil {
				changes = append(changes, *dependabot)
			}

			pinner, err := newPinner(cmd.Context(), a)
			if err != nil {
				return err
			}
			vet, err := pinner.Vet(cmd.Context(), tag)
			if err != nil {
				return githubError(err)
			}
			if commit := version.Commit(); github.IsCommitSHA(commit) && !strings.EqualFold(commit, vet.SHA) {
				return usefulerror.NewUsefulError().WithCode(CodeGitHub).
					WithHumanError(fmt.Sprintf("The tag %s of safedep/vet names the commit %s, and this vet comes from the commit %s", tag, vet.SHA, commit)).
					WithHelp("Install the vet release again, or report the tag to SafeDep.").
					WithMsg("the release tag does not name the commit of this build")
			}
			checkout, _, err := pinner.NewestCheckout(cmd.Context(), "")
			if err != nil {
				return githubError(err)
			}
			changes = append([]change{{path: wfPath, before: wf, after: githubci.Workflow(vet, checkout)}}, changes...)

			if dryRun {
				return printDiff(changes)
			}
			if err := repo.write(changes); err != nil {
				return err
			}
			return nextSteps(repo.dir, changes)
		},
	}
	f := c.Flags()
	f.BoolVar(&force, "force", false, "Replace the files that exist")
	f.BoolVar(&withPolicy, "policy", false, "Also write a starter policy file")
	f.BoolVar(&dryRun, "dry-run", false, "Print the diff and write nothing")
	return c
}

func rootOf(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return "."
}

func newPinner(ctx context.Context, a *app.App) (githubci.Pinner, error) {
	rt, err := a.Config(app.ConfigOptions{})
	if err != nil {
		return githubci.Pinner{}, err
	}
	client, err := github.NewClient(ctx, github.DefaultProvider(), rt.Config.GitHub.APIURL, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return githubci.Pinner{}, err
	}
	return githubci.Pinner{Client: client, Now: time.Now}, nil
}

// githubError gives an error of the GitHub API a reason and a help text.
func githubError(err error) error {
	help := "Check the network, then run the command again."
	if errors.Is(err, githubci.ErrNoRelease) {
		help = "Run the command again after the cooldown."
	} else if _, token := github.Reason(err); token {
		help = "Set GITHUB_TOKEN or run gh auth login, then run the command again."
	}
	return usefulerror.NewUsefulError().WithCode(CodeGitHub).WithHumanError(err.Error()).WithHelp(help).WithMsg(err.Error())
}

// repository is the root of a GitHub repository. Each read and write stays
// in it.
type repository struct {
	dir  string
	root *os.Root
}

// openRepo opens dir, the root of a GitHub repository.
func openRepo(dir string) (*repository, error) {
	if !githubci.IsRepository(dir) {
		return nil, app.UsageErrorCode(CodePlatform,
			fmt.Sprintf("vet ci knows only GitHub, and %s has no github.com origin and no .github directory", dir),
			"See "+ciDocs+" to run vet in another CI.")
	}
	if top, ok := github.WorktreeRoot(dir); ok && !sameDir(top, dir) {
		return nil, app.UsageError(fmt.Sprintf("%s is not the root of its git repository", dir),
			"Run the command in the root of the repository, where GitHub reads .github")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &repository{dir: dir, root: root}, nil
}

func sameDir(a, b string) bool {
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

func (r *repository) close() {
	if err := r.root.Close(); err != nil {
		tui.Warning("close %s: %v", r.dir, err)
	}
}

// read returns the file at the slash path rel, or nil when it does not
// exist.
func (r *repository) read(rel string) ([]byte, error) {
	data, err := r.root.ReadFile(filepath.FromSlash(rel))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// first returns the first of names that exists, or the first name with
// nil data.
func (r *repository) first(names []string) (string, []byte, error) {
	for _, name := range names {
		data, err := r.read(name)
		if err != nil || data != nil {
			return name, data, err
		}
	}
	return names[0], nil, nil
}

// write writes each change through a temporary file and a rename. It never
// writes through a symbolic link.
func (r *repository) write(changes []change) error {
	for _, c := range changes {
		name := filepath.FromSlash(c.path)
		if info, err := r.root.Lstat(name); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("vet does not write %s, because it is a symbolic link", c.path)
		}
		if err := r.root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		tmp := filepath.Join(filepath.Dir(name), ".vet-"+path.Base(c.path)+".tmp")
		if err := r.root.WriteFile(tmp, c.after, 0o644); err != nil {
			return err
		}
		if err := r.root.Rename(tmp, name); err != nil {
			return errors.Join(err, r.root.Remove(tmp))
		}
		tui.Success("Wrote %s", c.path)
	}
	return nil
}

// change is one file that the command writes. before is nil for a new
// file.
type change struct {
	path          string
	before, after []byte
}

// dependabotChange returns the change of the Dependabot config, or nil.
// It is best effort: vet never changes a setting of the user.
func dependabotChange(repo *repository) (*change, error) {
	renovate, err := githubci.UsesRenovate(repo.dir)
	if err != nil {
		return nil, err
	}
	if renovate {
		tui.Info("vet adds no Dependabot entry, because the repository uses Renovate. Renovate can move the action pins.")
		return nil, nil
	}
	name, old, err := repo.first(githubci.DependabotPaths)
	if err != nil {
		return nil, err
	}
	updated, result := githubci.AddDependabot(old)
	switch result {
	case githubci.DependabotPresent:
		tui.Info("vet leaves the Dependabot config %s as it is, because it has a github-actions entry", name)
		return nil, nil
	case githubci.DependabotManual:
		tui.Warning("vet cannot add the github-actions entry to %s with new lines only. Add this entry to the updates list:\n%s",
			name, strings.TrimRight(githubci.DependabotEntry, "\n"))
		return nil, nil
	}
	return &change{path: name, before: old, after: updated}, nil
}

func printDiff(changes []change) error {
	for _, c := range changes {
		if bytes.Equal(c.before, c.after) {
			continue
		}
		if _, err := fmt.Fprintf(output.Stdout(), "--- %s\n%s", c.path, escape.Text(diff.Render(string(c.before), string(c.after)))); err != nil {
			return err
		}
	}
	return nil
}

// nextSteps prints the commands that commit the files, the badge and the
// settings that make vet a gate.
func nextSteps(dir string, changes []change) error {
	git := "git"
	if dir != "." {
		git += " -C " + dir
	}
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.path)
	}
	hints := []string{
		"Commit the files in a pull request:",
		"  " + git + " add " + strings.Join(paths, " "),
		"  " + git + ` commit -m "Add vet to CI"`,
		"Make the vet job a required check in the branch ruleset.",
		"Add the workflows directory .github/workflows/ to CODEOWNERS",
	}
	if repo := github.OriginRepo(dir); repo != "" {
		url := "https://github.com/" + repo + "/actions/workflows/" + path.Base(changes[0].path)
		hints = append(hints, "Badge for the README:", fmt.Sprintf("  [![vet](%s/badge.svg)](%s)", url, url))
	}
	return tui.Hint("%s", strings.Join(hints, "\n"))
}

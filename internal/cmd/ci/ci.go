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
	"path/filepath"
	"strings"
	"time"

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

// CodePlatform is the error code of a repository on a CI platform that
// vet ci does not know.
const CodePlatform = "usage_ci_platform"

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

vet also adds a github-actions entry with a one day cooldown to
.github/dependabot.yml, so Dependabot moves the pins. vet only adds lines
at the end of the file. When it cannot, it prints the entry for you to
add. A repository with a Renovate config gets no entry.

--policy also writes .github/vet/policy.yml with the starter rules of vet
policy init. --force replaces files that exist. --dry-run prints the diff
and writes nothing. DIR is the root of the repository. The default is the
current directory.`,
		Example: `  vet ci init --dry-run    # Show the files and write nothing
  vet ci init              # Add the workflow
  vet ci init --policy     # Add the workflow and a starter policy`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := rootOf(args)
			if !githubci.IsRepository(root) {
				return app.UsageErrorCode(CodePlatform,
					fmt.Sprintf("vet ci init knows only GitHub, and %s has no github.com origin and no .github directory", root),
					"See docs/ci.md to run vet in another CI.")
			}
			tag, ok := github.ReleaseTag(version.Version())
			if !ok {
				return app.UsageError("vet ci init pins the action to this vet release, and this vet is a development build",
					"Install a release of vet, or copy the workflow from docs/github-action.md.")
			}
			pinner, err := newPinner(cmd.Context(), a)
			if err != nil {
				return err
			}
			vet, err := pinner.Vet(cmd.Context(), tag)
			if err != nil {
				return err
			}
			checkout, err := pinner.NewestCheckout(cmd.Context())
			if err != nil {
				return err
			}

			var changes []change
			wf, err := read(root, githubci.WorkflowPath)
			if err != nil {
				return err
			}
			if wf != nil && !force {
				return app.UsageError(githubci.WorkflowPath+" exists",
					"Run vet ci update to move its pins, or pass --force to replace it.")
			}
			changes = append(changes, change{path: githubci.WorkflowPath, before: wf, after: githubci.Workflow(vet, checkout)})

			if withPolicy {
				old, err := read(root, githubci.PolicyPath)
				switch {
				case err != nil:
					return err
				case old != nil && !force:
					tui.Info("vet keeps %s, because it exists. Pass --force to replace it.", githubci.PolicyPath)
				default:
					changes = append(changes, change{path: githubci.PolicyPath, before: old, after: []byte(policy.Starter)})
				}
			}

			dependabot, err := dependabotChange(root)
			if err != nil {
				return err
			}
			if dependabot != nil {
				changes = append(changes, *dependabot)
			}

			if dryRun {
				return printDiff(changes)
			}
			if err := write(root, changes); err != nil {
				return err
			}
			return nextSteps(root, changes)
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

// change is one file that the command writes. before is nil for a new
// file.
type change struct {
	path          string
	before, after []byte
}

// read returns the file at the slash path rel under root, or nil when it
// does not exist.
func read(root, rel string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// dependabotChange returns the change of the Dependabot config, or nil.
// It is best effort: vet never changes a line of the user.
func dependabotChange(root string) (*change, error) {
	renovate, err := githubci.UsesRenovate(root)
	if err != nil {
		return nil, err
	}
	if renovate {
		tui.Info("vet adds no Dependabot entry, because the repository uses Renovate. Renovate can move the action pins.")
		return nil, nil
	}
	old, err := read(root, githubci.DependabotPath)
	if err != nil {
		return nil, err
	}
	updated, result := githubci.AddDependabot(old)
	switch result {
	case githubci.DependabotPresent:
		tui.Info("%s has a github-actions entry already. vet leaves it as it is.", githubci.DependabotPath)
		return nil, nil
	case githubci.DependabotManual:
		tui.Warning("vet cannot add the github-actions entry to %s with new lines only. Add this entry to updates:", githubci.DependabotPath)
		return nil, tui.Hint("%s", strings.TrimRight(githubci.DependabotEntry, "\n"))
	}
	return &change{path: githubci.DependabotPath, before: old, after: updated}, nil
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

func write(root string, changes []change) error {
	for _, c := range changes {
		path := filepath.Join(root, filepath.FromSlash(c.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, c.after, 0o644); err != nil {
			return err
		}
		tui.Success("Wrote %s", c.path)
	}
	return nil
}

// nextSteps prints the commands that commit the files, the badge and the
// settings that make vet a gate.
func nextSteps(root string, changes []change) error {
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.path)
	}
	hints := []string{
		"Commit the files in a pull request:",
		"  git add " + strings.Join(paths, " "),
		`  git commit -m "Add vet to CI"`,
		"Make the vet job a required check in the branch ruleset, and add .github/workflows/ to CODEOWNERS.",
	}
	if repo := github.OriginRepo(root); repo != "" {
		url := "https://github.com/" + repo + "/actions/workflows/vet.yml"
		hints = append(hints, "Badge for the README:", fmt.Sprintf("  [![vet](%s/badge.svg)](%s)", url, url))
	}
	return tui.Hint("%s", strings.Join(hints, "\n"))
}

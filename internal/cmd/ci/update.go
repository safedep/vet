package ci

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/ci/githubci"
	"github.com/safedep/vet/v2/internal/fix"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func newUpdate(a *app.App) *cobra.Command {
	var dryRun bool
	c := &cobra.Command{
		Use:   "update [DIR]",
		Short: "Move the action pins of the vet workflow",
		Long: `Move the safedep/vet and actions/checkout pins in
.github/workflows/vet.yml to the newest release that is older than 24
hours. vet takes an immutable stable release of vet v2, or a pre-release
while v2 has no stable release. actions/checkout stays in its major
version. A pin never moves to an older release.

vet edits only the uses: lines of the two actions, and writes the new
tag as the comment. Each other line stays. Use it when Dependabot or
Renovate does not move the pins. --dry-run prints the diff and writes
nothing. DIR is the root of the repository. The default is the current
directory.`,
		Example: `  vet ci update --dry-run   # Show the new pins and write nothing
  vet ci update             # Move the pins`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, err := openRepo(rootOf(args))
			if err != nil {
				return err
			}
			defer repo.close()
			wfPath, wf, err := repo.first(githubci.WorkflowPaths)
			if err != nil {
				return err
			}
			if wf == nil {
				return app.UsageError("The repository has no vet workflow", "Run vet ci init to add it.")
			}
			current, err := fix.PinnedTags(wf)
			if err != nil {
				return app.UsageError(fmt.Sprintf("The workflow %s is not valid YAML: %v", wfPath, err), "Fix the file, then run the command again.")
			}
			if _, ok := current[githubci.VetRepo]; !ok {
				return app.UsageError(fmt.Sprintf("The workflow %s has no safedep/vet action pinned to a commit with a tag comment", wfPath),
					"Run vet ci init --force to write the workflow again.")
			}

			pinner, err := newPinner(cmd.Context(), a)
			if err != nil {
				return err
			}
			pins := map[string]fix.Pin{}
			vet, ok, err := pinner.NewestVet(cmd.Context(), current[githubci.VetRepo])
			if err != nil {
				return githubError(err)
			}
			if ok {
				pins[githubci.VetRepo] = vet
			}
			if tag, found := current[githubci.CheckoutRepo]; found {
				checkout, ok, err := pinner.NewestCheckout(cmd.Context(), tag)
				if err != nil {
					return githubError(err)
				}
				if ok {
					pins[githubci.CheckoutRepo] = checkout
				}
			}
			plan, err := fix.PlanRepins(cmd.Context(), fix.RepinOptions{Root: repo.dir, Files: []string{wfPath}, Pins: pins})
			if err != nil {
				return err
			}
			for _, f := range plan.Failures {
				tui.Warning("%s:%d: %s: %s", escape.Line(f.Path), f.Line, escape.Line(f.Action), escape.Line(f.Reason))
			}
			switch {
			case plan.Edits() == 0:
				tui.Info("The pins of %s are up to date", wfPath)
				return nil
			case dryRun:
				_, err := fmt.Fprint(output.Stdout(), escape.Text(plan.Diff()))
				return err
			}
			if err := plan.Apply(); err != nil {
				return err
			}
			tui.Success("Moved %s in %s", humanize.Count(plan.Edits(), "pin"), wfPath)
			return nil
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Print the diff and write nothing")
	return c
}

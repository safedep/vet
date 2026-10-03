// Package fix holds the "vet fix" commands. A scan never writes the
// scanned repository. A fix writes it only when the user runs the fix.
package fix

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vfix "github.com/safedep/vet/v2/internal/fix"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/printer"
)

// CodeUnresolved is the error code of a fix that could not resolve every
// action. The command exits with code 3.
const CodeUnresolved = "fix_unresolved"

// New returns the "vet fix" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "fix",
		Short: "Apply explicit fixes to a repository",
		Long: `The fix commands change the files of a repository. vet scan never writes
the repository, so each fix is a command of its own.`,
	}
	gha := &cobra.Command{
		Use:   "github-actions",
		Short: "Fix the GitHub Actions workflows of a repository",
		Long:  `Fix the GitHub Actions workflows and the composite actions of a repository.`,
	}
	gha.AddCommand(newRun(a))
	c.AddCommand(gha)
	return c
}

func newRun(a *app.App) *cobra.Command {
	var dryRun bool
	c := &cobra.Command{
		Use:   "run [DIR]",
		Short: "Pin third-party GitHub Actions to commit SHAs",
		Long: `Pin each third-party action that a workflow or a composite action uses by
a tag or a branch to the commit SHA of that ref, and keep the ref in a
comment. vet resolves the SHA with the GitHub API, with GITHUB_TOKEN or
the token of the gh CLI when one exists. Local actions, Docker images,
actions of the same repository and expressions do not change. vet edits
only the uses: value, so the file keeps its format.

--dry-run prints the diff and writes nothing. DIR is the root of the
repository. The default is the current directory.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			rt, err := a.Config(app.ConfigOptions{})
			if err != nil {
				return err
			}
			client, err := github.NewClient(cmd.Context(), github.DefaultProvider(), rt.Config.GitHub.APIURL, &http.Client{Timeout: 30 * time.Second})
			if err != nil {
				return err
			}
			plan, err := vfix.PlanPins(cmd.Context(), vfix.PinOptions{Root: root, Resolver: vfix.GitHubResolver{Client: client}})
			if err != nil {
				return err
			}
			for _, f := range plan.Failures {
				tui.Warning("%s:%d: %s: %s", escape.Line(f.Path), f.Line, escape.Line(f.Action), escape.Line(f.Reason))
				tui.Faint("  %s", escape.Line(f.Error))
			}
			if err := printPlan(a, plan, dryRun); err != nil {
				return err
			}
			if !dryRun {
				if err := plan.Apply(); err != nil {
					return err
				}
			}
			summary(plan, dryRun)
			if len(plan.Failures) > 0 {
				msg := "vet could not pin " + humanize.Count(len(plan.Failures), "action")
				help := "Check the action names and the refs, then run the fix again."
				if plan.NeedsToken() {
					help = "Set GITHUB_TOKEN or run gh auth login, then run the fix again."
				}
				return usefulerror.NewUsefulError().WithCode(CodeUnresolved).WithHumanError(msg).WithHelp(help).WithMsg(msg)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Print the diff and write nothing")
	return c
}

// printPlan prints the diff for a dry run in a human format, and the plan
// in every other case.
func printPlan(a *app.App, plan *vfix.Plan, dryRun bool) error {
	p, err := a.Printer()
	if err != nil {
		return err
	}
	if dryRun && (p.Format() == printer.Table || p.Format() == printer.Plain) {
		_, err := fmt.Fprint(output.Stdout(), escape.Text(plan.Diff()))
		return err
	}
	rows := printer.Rows{Headers: []string{"FILE", "LINE", "ACTION", "REF", "SHA"}}
	for _, f := range plan.Files {
		for _, e := range f.Edits {
			rows.Rows = append(rows.Rows, []string{escape.Line(f.Path), strconv.Itoa(e.Line), escape.Line(e.Action), escape.Line(e.Ref), e.SHA})
		}
	}
	if len(rows.Rows) == 0 && p.Format() == printer.Table {
		return nil // The summary line on stderr says that vet pinned no action.
	}
	return p.Print(plan, rows)
}

func summary(plan *vfix.Plan, dryRun bool) {
	switch {
	case plan.Edits() == 0 && len(plan.Failures) > 0:
		return // The error of the command counts the actions that failed.
	case plan.Edits() == 0:
		tui.Info("No action to pin.")
	case dryRun:
		tui.Info("vet would pin %s in %s. Run without --dry-run to write them.", humanize.Count(plan.Edits(), "action"), humanize.Count(len(plan.Files), "file"))
	default:
		tui.Success("Pinned %s in %s.", humanize.Count(plan.Edits(), "action"), humanize.Count(len(plan.Files), "file"))
	}
}

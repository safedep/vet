// Package scan holds the "vet scan" command.
package scan

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
)

// New returns the "vet scan" command.
func New(a *app.App) *cobra.Command {
	var o runner.Options
	c := &cobra.Command{
		Use:   "scan [TARGET]",
		Short: "Scan a project, a repository, an image, an SBOM or a package",
		Long: `Scan finds supply chain risk in a target: a directory (the default is the
current directory), a git repository URL, a container image (oci://IMAGE or
an image .tar file), an SBOM file or a package URL (pkg:npm/name@1.0.0).

vet extracts the packages, checks them with SafeDep Insights and Malysis,
runs the controls, and applies the gate. A plain scan reports and exits 0.
--fail-on and --policy set a gate that exits 1 when it fails.

--base-ref compares the target with a git ref and reports only what the
change adds. vet saves each scan, so "vet report show" renders it again
with no new scan, and an interrupted scan continues on the next run.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Target = "."
			if len(args) == 1 {
				o.Target = args[0]
			}
			return runner.Scan(cmd.Context(), a, o)
		},
	}
	f := c.Flags()
	f.StringVar(&o.BaseRef, "base-ref", "", "Report only what the target changes since this git ref (pull request mode)")
	f.StringVar(&o.FailOn, "fail-on", "", "Fail with exit code 1 on a finding at this severity or above: critical, high, medium, low or info")
	f.StringVar(&o.Policy, "policy", "", "Policy v2 file or directory that sets the rules and the suppressions")
	f.StringArrayVar(&o.Reports, "report", nil, "Also write the report as FORMAT=PATH, for example json=vet.json. Repeatable")
	f.BoolVar(&o.Strict, "strict", false, "Exit with code 3 when a diagnostic exists, for example when a backend did not answer")
	f.BoolVar(&o.Resume, "resume", false, "Continue the stopped scan of the target, however old it is")
	f.BoolVar(&o.Fresh, "fresh", false, "Start a new scan, and do not continue a stopped one")
	f.BoolVar(&o.NoCache, "no-cache", false, "Do not read or write the enrichment cache")
	f.StringArrayVar(&o.Exclude, "exclude", nil, "Skip the paths that match this glob, relative to the target. Repeatable")
	f.IntVar(&o.CooldownDays, "cooldown-days", 0, "Cooldown window in days. Sets plugins.dependency-cooldown.options.days")
	o.State.Register(f)
	c.MarkFlagsMutuallyExclusive("resume", "fresh")
	return c
}

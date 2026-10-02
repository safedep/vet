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
	f.StringArrayVar(&o.Exclude, "exclude", nil, "Skip the paths that match this glob, relative to the target. Repeatable")
	o.RegisterFlags(c)
	return c
}

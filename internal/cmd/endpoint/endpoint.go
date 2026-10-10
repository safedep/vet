// Package endpoint holds the "vet endpoint" commands. They check this
// machine, not a project.
package endpoint

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/plugins/sources/endpoint"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/report"
)

// Error codes of vet endpoint audit.
const (
	// CodeNeedsRoot is the error code of --all-users without root.
	CodeNeedsRoot = "usage_needs_root"
	// CodeProjects is the error code of a --projects folder that does not
	// exist.
	CodeProjects = "usage_projects_dir"
)

// New returns the "vet endpoint" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "endpoint",
		Short: "Check this machine",
		Long: `vet endpoint checks the machine that it runs on: the IDE extensions, the
MCP servers, the AI agents and their skills, the global packages and the
agent and editor config files. vet scan checks a project and never reads
the home directory.`,
	}
	c.AddCommand(newAudit(a, endpoint.DefaultSystem()))
	return c
}

func newAudit(a *app.App, sys endpoint.System) *cobra.Command {
	var o runner.Options
	var src endpoint.Options
	c := &cobra.Command{
		Use:   "audit",
		Short: "Audit the tools on this machine",
		Long: `Audit lists the tools on this machine and checks them. The report holds the
AI tools, MCP servers, agent skills and editor plugins as inventory. vet
checks the IDE extensions and the global npm packages like the packages of
a project, and checks the agent and editor config files that run commands.

vet reads the home directory of the current user. --all-users reads the
home directory of every user and the machine-wide global packages, and
needs root: run it with sudo. --projects DIR also checks the repositories
under DIR: their agent and editor configs, build configs, assets and
scripts. A worm that spreads to each repository on a machine changes
these files. The target key is endpoint:<hostname>, so "vet report show"
and "vet report diff" compare the audits of a machine.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if src.AllUsers && !sys.Privileged() {
				return app.UsageErrorCode(CodeNeedsRoot, "--all-users needs root",
					"Run sudo vet endpoint audit --all-users, or drop --all-users to audit your own user.")
			}
			if err := endpoint.CheckProjects(src.Projects); err != nil {
				return app.UsageErrorCode(CodeProjects, err.Error(), "Pass a folder that holds your repositories, such as --projects ~/code.")
			}
			o.Kind = report.ScanKindEndpoint
			o.Source = endpoint.New(src, sys)
			return runner.Scan(cmd.Context(), a, o)
		},
	}
	c.Flags().BoolVar(&src.AllUsers, "all-users", false, "Audit every user on the machine. Needs root")
	c.Flags().StringSliceVar(&src.Projects, "projects", nil, "Also check the repositories under this folder. Repeat it for more folders")
	o.RegisterFlags(c)
	return c
}

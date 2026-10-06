package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/config/appdir"
	vpolicy "github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/tui"
)

func newInit(a *app.App) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init [NAME]",
		Short: "Write a starter policy file",
		Long: `Write a starter policy v2 file with rules for malware, critical
vulnerabilities, risky workflows and fresh packages. A NAME with an
extension or a directory is a path. Another NAME writes policies/NAME.yml
in the vet config directory, and --policy NAME then finds it. The default
NAME is "default". vet does not replace a file that exists unless --force
is set.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := "default"
			if len(args) == 1 {
				name = args[0]
			}
			path := name
			if vconfig.IsPolicyName(name) {
				rt, err := a.Config(app.ConfigOptions{})
				if err != nil {
					return err
				}
				if err := appdir.Ensure(rt.PolicyDir()); err != nil {
					return err
				}
				path = rt.PolicyFile(name)
			}
			if _, err := os.Stat(path); err == nil && !force {
				return app.UsageError(fmt.Sprintf("%s exists", path), "Pass --force to replace it, or name another file.")
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := os.WriteFile(path, []byte(vpolicy.Starter), 0o600); err != nil {
				return err
			}
			tui.Success("Wrote %s. vet scan --policy %s applies it.", path, name)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "Replace a file that exists")
	return c
}

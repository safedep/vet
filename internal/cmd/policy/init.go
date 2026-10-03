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
	"github.com/safedep/vet/v2/internal/tui"
)

// Starter is the policy that "vet policy init" writes. It fails on the
// controls that need no tuning and warns on the others.
const Starter = `# vet policy v2. vet scan --policy FILE applies it.
# vet policy schema get prints the fields that a rule reads.
version: 2

rules:
  - id: no-malware
    description: A malicious or suspicious package fails the gate.
    when: finding.family == "malware"
    action: fail
  - id: no-critical-vulnerability
    when: finding.control_id == "vulnerability" && finding.severity == "critical"
    action: fail
  - id: workflow-risk
    when: finding.control_id in ["dangerous-trigger", "template-injection"]
    action: fail
  - id: fresh-packages
    description: A version that the registry published in the last 5 days.
    when: package.days_since_publish < 5
    action: warn

# A suppression hides findings from the gate. The findings stay in the
# report. Set id, purl or control, a reason, and an optional expiry.
suppressions: []
#  - purl: pkg:npm/left-pad@1.3.0
#    control: dependency-cooldown
#    reason: Reviewed. The maintainer published a fix.
#    expires: 2026-12-31
`

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
			if err := os.WriteFile(path, []byte(Starter), 0o600); err != nil {
				return err
			}
			tui.Success("Wrote %s. vet scan --policy %s applies it.", path, name)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "Replace a file that exists")
	return c
}

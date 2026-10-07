package policy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/policysources/file"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/printer"
)

// Result is the output of "vet policy validate".
type Result struct {
	Sources      []string   `json:"sources"`
	Rules        int        `json:"rules"`
	Suppressions int        `json:"suppressions"`
	RuleList     []RuleInfo `json:"rule_list"`
}

// RuleInfo says what a rule runs on: each finding, or each package.
type RuleInfo struct {
	ID     string        `json:"id"`
	Source string        `json:"source"`
	Action policy.Action `json:"action"`
	Scope  policy.Scope  `json:"scope"`
}

func newValidate(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "validate [FILE|NAME]",
		Short: "Check a policy file",
		Long: `Check a policy v2 file, or each .yml and .yaml file of a directory: the
version, each rule, its CEL condition and its action, and each
suppression. A NAME with no extension and no directory is
policies/NAME.yml in the vet config directory, as vet policy init writes
it. The default is the file of the policy.file config key. vet lists
every problem and exits 2. validate changes nothing.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			if path == "" || vconfig.IsPolicyName(path) {
				rt, err := a.Config(app.ConfigOptions{})
				if err != nil {
					return err
				}
				if path == "" {
					path = rt.Config.Policy.File
				}
				path = rt.ResolvePolicy(path)
			}
			if path == "" {
				return app.UsageError("no policy file to check", "Name a file, or set policy.file in the config file.")
			}
			docs, err := file.New(path).Policies(cmd.Context())
			if err != nil {
				return err
			}
			p, err := policy.Load(docs)
			if err != nil {
				return err
			}
			pr, err := a.Printer()
			if err != nil {
				return err
			}
			r := Result{Sources: p.Sources, Rules: len(p.Rules), Suppressions: len(p.Suppressions), RuleList: []RuleInfo{}}
			rows := printer.Rows{
				Title:   fmt.Sprintf("Valid: %s, %s", humanize.Count(r.Rules, "rule"), humanize.Count(r.Suppressions, "suppression")),
				Headers: []string{"RULE", "ACTION", "RUNS ON", "FILE"},
				Empty:   "The policy has no rules.",
			}
			for i := range p.Rules {
				rule := &p.Rules[i]
				info := RuleInfo{ID: rule.ID, Source: rule.Source(), Action: rule.Action, Scope: rule.Scope()}
				r.RuleList = append(r.RuleList, info)
				rows.Rows = append(rows.Rows, []string{info.ID, string(info.Action), "each " + string(info.Scope), info.Source})
			}
			return pr.Print(r, rows)
		},
	}
}

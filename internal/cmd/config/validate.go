package config

import (
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/tui"
)

func newValidate(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Check a config file",
		Long: `Check a config file: the YAML, each value and each key. An unknown key is
an error here, with the closest known key, although a scan only warns.
The default is the config file of the run. validate changes nothing.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			} else {
				rt, err := a.Config(app.ConfigOptions{})
				if err != nil {
					return err
				}
				path = rt.File
			}
			if path == "" {
				tui.Info("No config file. The defaults apply.")
				return nil
			}
			l, err := vconfig.Load(vconfig.LoadOptions{ConfigFile: path, LookupEnv: func(string) (string, bool) { return "", false }})
			if err != nil {
				return err
			}
			if err := l.ValidateStrict(); err != nil {
				return err
			}
			tui.Success("%s is valid.", path)
			return nil
		},
	}
}

func dirOf(path string) string { return filepath.Dir(path) }

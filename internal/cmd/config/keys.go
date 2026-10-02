package config

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
)

func newGet(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "get KEY",
		Short: "Print one config value",
		Long:  `Print the effective value of one key. -o json prints the value and its source.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rt, err := a.Config(app.ConfigOptions{})
			if err != nil {
				return err
			}
			v, err := vconfig.Get(rt.Config, args[0])
			if err != nil {
				return err
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			e := Entry{Key: args[0], Value: v, Origin: rt.Origins.Of(args[0])}
			return p.Print(e, printer.Rows{Rows: [][]string{{escape.Line(text(v))}}})
		},
	}
}

func newSet(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "set KEY VALUE",
		Short: "Set a key in the user config file",
		Long: `Set a key in the user config file, or in the --config file. vet checks the
key, the value and the whole file before it writes. It keeps the comments
and the key order of the file. A list takes values with commas, for
example "vendor,testdata".`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			rt, path, err := target(a)
			if err != nil {
				return err
			}
			if err := vconfig.SetInFile(path, args[0], args[1]); err != nil {
				return err
			}
			managedWarning(rt)
			tui.Success("Set %s in %s.", args[0], path)
			return nil
		},
	}
}

func newDelete(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "delete KEY",
		Short: "Remove a key from the user config file",
		Long:  `Remove a key from the user config file, or from the --config file, so that the next layer down applies.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rt, path, err := target(a)
			if err != nil {
				return err
			}
			if err := vconfig.DeleteInFile(path, args[0]); err != nil {
				return err
			}
			managedWarning(rt)
			tui.Success("Removed %s from %s.", args[0], path)
			return nil
		},
	}
}

// target returns the file that set and delete edit: --config, or the user
// file.
func target(a *app.App) (*vconfig.Runtime, string, error) {
	rt, err := a.Config(app.ConfigOptions{})
	if err != nil {
		return nil, "", err
	}
	if a.Globals.ConfigFile != "" {
		return rt, a.Globals.ConfigFile, nil
	}
	return rt, rt.UserFile(), nil
}

func managedWarning(rt *vconfig.Runtime) {
	if rt.FileLayer == vconfig.LayerManaged {
		tui.Warning("The managed file %s is in force, so the user file has no effect.", rt.File)
	}
}

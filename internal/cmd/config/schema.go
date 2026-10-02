package config

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/internal/plugins/cloud/tenantpolicy"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
)

func newSchemaGet(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Print the JSON Schema of the config file",
		Long: `Print the JSON Schema of the config file, with the options of each
built-in plugin. A YAML language server reads it to check the file in an
editor.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if out := a.Globals.Output; out != "" && out != "json" {
				return app.UsageError(fmt.Sprintf("-o %s: the schema is JSON only", out), "Use -o json, or no -o.")
			}
			schemas, err := pluginSchemas()
			if err != nil {
				return err
			}
			b, err := vconfig.Schema(schemas)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(output.Stdout(), string(b))
			return err
		},
	}
}

// pluginSchemas returns the options schema of each built-in plugin that
// implements plugin.Schemer.
func pluginSchemas() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, s := range controls.Builtin() {
		c, err := s.New(plugin.MapConfig(nil))
		if err != nil {
			return nil, err
		}
		if sc, ok := c.(plugin.Schemer); ok {
			out[s.Name] = sc.OptionsSchema()
		}
	}
	for _, s := range sinks.Builtin() {
		sk, err := s.New(plugin.MapConfig(nil))
		if err != nil {
			return nil, err
		}
		if sc, ok := sk.(plugin.Schemer); ok {
			out[s.Name] = sc.OptionsSchema()
		}
	}
	tp, err := tenantpolicy.New(plugin.MapConfig(nil))
	if err != nil {
		return nil, err
	}
	if sc, ok := tp.(plugin.Schemer); ok {
		out[tenantpolicy.Name] = sc.OptionsSchema()
	}
	inv, err := inventory.New(plugin.MapConfig(nil), nil)
	if err != nil {
		return nil, err
	}
	out[inventory.Name] = inv.OptionsSchema()
	return out, nil
}

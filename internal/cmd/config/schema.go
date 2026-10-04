package config

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/builtin"
	"github.com/safedep/vet/v2/internal/tui/output"
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
// has options.
func pluginSchemas() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, p := range builtin.Plugins() {
		schema, err := p.Schema()
		if err != nil {
			return nil, err
		}
		if schema != nil {
			out[p.Name] = schema
		}
	}
	return out, nil
}

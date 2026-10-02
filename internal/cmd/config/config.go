// Package config holds the "vet config" commands. They read the effective
// config of a run and edit the user config file.
package config

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
)

// New returns the "vet config" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Show, edit and check the vet config",
		Long: `vet reads its config from the defaults, the managed file, the user file
(or --config), the VET_* variables and the flags, from the lowest layer to
the highest. The config commands show the effective config and the source
of each value, edit the user file, and check a file.`,
	}
	schema := &cobra.Command{
		Use:   "schema",
		Short: "Read the JSON Schema of the config file",
		Long:  `Read the JSON Schema of the config file, for editors and agents.`,
	}
	schema.AddCommand(newSchemaGet(a))
	c.AddCommand(newShow(a), newGet(a), newSet(a), newDelete(a), newEdit(a), newValidate(a), schema)
	return c
}

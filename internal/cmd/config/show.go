package config

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
)

// Entry is one key of the effective config.
type Entry struct {
	Key    string         `json:"key"`
	Value  any            `json:"value"`
	Origin vconfig.Origin `json:"origin"`
}

// Dir is one directory of vet and the rule that chose it.
type Dir struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Origin string `json:"origin"`
}

// Show is the output of "vet config show".
type Show struct {
	File        string  `json:"file,omitempty"`
	Directories []Dir   `json:"directories"`
	Keys        []Entry `json:"keys"`
}

func newShow(a *app.App) *cobra.Command {
	var origin bool
	c := &cobra.Command{
		Use:   "show",
		Short: "Show the effective config",
		Long: `Show each key of the effective config with its value. --origin adds the
source of each value: the default, the managed file, the user file, a
VET_* variable or a flag. -o json always holds the source.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rt, err := a.Config(app.ConfigOptions{})
			if err != nil {
				return err
			}
			vals, err := vconfig.Values(rt.Config)
			if err != nil {
				return err
			}
			out := Show{File: rt.File}
			for _, k := range []appdir.Kind{appdir.Config, appdir.State, appdir.Cache, appdir.Managed} {
				out.Directories = append(out.Directories, Dir{Kind: string(k), Path: rt.Dirs.Get(k), Origin: rt.Dirs.Origin[k]})
			}
			rows := printer.Rows{Headers: []string{"KEY", "VALUE"}}
			if origin {
				rows.Headers = append(rows.Headers, "ORIGIN")
			}
			for _, k := range vconfig.SortedKeys(vals) {
				e := Entry{Key: k, Value: vals[k], Origin: rt.Origins.Of(k)}
				out.Keys = append(out.Keys, e)
				row := []string{k, escape.Line(text(e.Value))}
				if origin {
					row = append(row, describe(e.Origin))
				}
				rows.Rows = append(rows.Rows, row)
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			return p.Print(out, rows)
		},
	}
	c.Flags().BoolVar(&origin, "origin", false, "Show the source of each value")
	return c
}

func text(v any) string {
	switch x := v.(type) {
	case nil:
		return `""`
	case string:
		if x == "" {
			return `""`
		}
		return x
	case []any, map[string]any:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
	return fmt.Sprint(v)
}

func describe(o vconfig.Origin) string {
	if o.Source == "" {
		return string(o.Layer)
	}
	return string(o.Layer) + " " + escape.Line(o.Source)
}

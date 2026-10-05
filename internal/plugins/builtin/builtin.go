// Package builtin is the one list of the built-in plugins that a plugins
// section of the config names. A command that needs the names, the option
// check or the option schema of every plugin reads them here. Add a new
// configurable plugin to Plugins, and each command picks it up.
package builtin

import (
	"cmp"
	"slices"

	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/internal/plugins/cloud/tenantpolicy"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/actionrefs"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/plugin"
)

// Plugin is a built-in plugin with a plugins section in the config.
type Plugin struct {
	Name string
	// Check builds the plugin from its options and returns the error.
	Check func(plugin.Config) error
	// Schema returns the JSON Schema of the options, or nil for a plugin
	// with no options.
	Schema func() ([]byte, error)
}

// Plugins returns the built-in plugins, sorted by name.
func Plugins() []Plugin {
	var out []Plugin
	for _, s := range controls.Builtin() {
		out = append(out, fromFactory(s.Name, s.New))
	}
	for _, s := range sinks.Builtin() {
		out = append(out, fromFactory(s.Name, s.New))
	}
	out = append(out,
		fromFactory(tenantpolicy.Name, tenantpolicy.New),
		fromFactory(inventory.Name, func(c plugin.Config) (*inventory.Syncer, error) { return inventory.New(c, nil) }),
		fromFactory(actionrefs.Name, func(c plugin.Config) (*actionrefs.Enricher, error) { return actionrefs.New(c, nil, "") }),
		// codeusage reads only plugins.codeusage.enabled.
		Plugin{Name: codeusage.Name, Check: func(plugin.Config) error { return nil }, Schema: func() ([]byte, error) { return nil, nil }},
	)
	slices.SortFunc(out, func(a, b Plugin) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Names returns the names of the built-in plugins, sorted.
func Names() []string {
	ps := Plugins()
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return names
}

func fromFactory[T any](name string, build func(plugin.Config) (T, error)) Plugin {
	return Plugin{
		Name:  name,
		Check: func(c plugin.Config) error { _, err := build(c); return err },
		Schema: func() ([]byte, error) {
			p, err := build(plugin.MapConfig(nil))
			if err != nil {
				return nil, err
			}
			if s, ok := any(p).(plugin.Schemer); ok {
				return s.OptionsSchema(), nil
			}
			return nil, nil
		},
	}
}

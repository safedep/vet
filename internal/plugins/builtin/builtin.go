// Package builtin is the one list of the built-in plugins that a plugins
// section of the config names. A command that needs the names, the option
// check or the option schema of every plugin reads them here. Add a new
// configurable plugin to Plugins, and each command picks it up.
package builtin

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/safedep/vet/v2/internal/config"
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
	config.Plugin
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
		out = append(out, fromFactory(config.Plugin{Name: s.Name, Description: s.Description, Switch: true, On: true}, s.New))
	}
	for _, s := range sinks.Builtin() {
		desc := fmt.Sprintf("Report format: %s. -o and --report select it.", s.Description)
		out = append(out, fromFactory(config.Plugin{Name: s.Name, Description: desc}, s.New))
	}
	out = append(out,
		fromFactory(config.Plugin{
			Name: tenantpolicy.Name, Switch: true,
			Description: "Adds the policy of your SafeDep Cloud tenant to the gate. It is not available yet.",
		}, tenantpolicy.New),
		fromFactory(config.Plugin{
			Name: inventory.Name, Switch: true, On: true,
			Description: "Sends the inventory of vet endpoint audit to SafeDep Cloud.",
		}, inventory.Decode),
		fromFactory(config.Plugin{
			Name: actionrefs.Name, Switch: true, On: true,
			Description: "Checks with the GitHub API that each action pinned to a commit uses a commit of its own repository.",
		}, func(c plugin.Config) (*actionrefs.Enricher, error) { return actionrefs.New(c, nil, "") }),
		Plugin{
			Plugin: config.Plugin{
				Name: codeusage.Name, Switch: true, On: true,
				Description: "Reads the source code for reachability, the call graph and the code capabilities. It needs a vet build with CGO.",
			},
			Check:  func(c plugin.Config) error { _, err := codeusage.ParseSettings(c); return err },
			Schema: func() ([]byte, error) { return codeusage.OptionsSchema(), nil },
		},
	)
	slices.SortFunc(out, func(a, b Plugin) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// ConfigPlugins returns the built-in plugins as the config sees them.
func ConfigPlugins() []config.Plugin {
	ps := Plugins()
	out := make([]config.Plugin, len(ps))
	for i, p := range ps {
		out[i] = p.Plugin
	}
	return out
}

// Enabled reports whether the config turns a plugin on. A plugin with no
// enabled key has its built-in state.
func Enabled(cfg *config.Config, name string) bool {
	for _, p := range Plugins() {
		if p.Name == name {
			return cfg.PluginEnabled(name, p.On)
		}
	}
	return false
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

func fromFactory[T any](p config.Plugin, build func(plugin.Config) (T, error)) Plugin {
	return Plugin{
		Plugin: p,
		Check:  func(c plugin.Config) error { _, err := build(c); return err },
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

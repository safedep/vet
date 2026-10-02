// Package controls lists the built-in control plugins and builds the ones
// that the configuration turns on.
package controls

import (
	"fmt"

	"github.com/safedep/vet/v2/internal/plugins/controls/agentconfig"
	"github.com/safedep/vet/v2/internal/plugins/controls/cooldown"
	"github.com/safedep/vet/v2/internal/plugins/controls/lockfile"
	"github.com/safedep/vet/v2/internal/plugins/controls/malware"
	"github.com/safedep/vet/v2/internal/plugins/controls/vuln"
	"github.com/safedep/vet/v2/internal/plugins/controls/workflow"
	"github.com/safedep/vet/v2/plugin"
)

// Spec is one built-in control plugin.
type Spec struct {
	Name string
	New  plugin.Factory[plugin.Control]
}

// Builtin returns the built-in control plugins, sorted by name. Each is on
// by default.
func Builtin() []Spec {
	return []Spec{
		{Name: agentconfig.Name, New: agentconfig.New},
		{Name: cooldown.Name, New: cooldown.New},
		{Name: lockfile.Name, New: lockfile.New},
		{Name: malware.Name, New: malware.New},
		{Name: vuln.Name, New: vuln.New},
		{Name: workflow.Name, New: workflow.New},
	}
}

// Settings are the plugins section of the configuration.
type Settings interface {
	PluginEnabled(name string, def bool) bool
	PluginOptions(name string) map[string]any
}

// Control is a built control plugin with its name.
type Control struct {
	Name   string
	Plugin plugin.Control
}

// Build builds each enabled control with its options.
func Build(s Settings) ([]Control, error) {
	var out []Control
	for _, spec := range Builtin() {
		if !s.PluginEnabled(spec.Name, true) {
			continue
		}
		c, err := spec.New(plugin.MapConfig(s.PluginOptions(spec.Name)))
		if err != nil {
			return nil, fmt.Errorf("plugins.%s.options: %w", spec.Name, err)
		}
		out = append(out, Control{Name: spec.Name, Plugin: c})
	}
	return out, nil
}

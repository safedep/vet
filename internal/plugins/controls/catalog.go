package controls

import (
	"github.com/safedep/vet/v2/plugin"
)

// Info is one control id of a built-in control plugin.
type Info struct {
	plugin.ControlInfo
	Plugin string `json:"plugin"`
}

// Catalog returns the control ids of the built-in control plugins, in
// plugin order. It builds each plugin with its default options.
func Catalog() ([]Info, error) {
	var out []Info
	for _, spec := range Builtin() {
		c, err := spec.New(plugin.MapConfig(nil))
		if err != nil {
			return nil, err
		}
		d, ok := c.(plugin.Describer)
		if !ok {
			continue
		}
		for _, info := range d.Controls() {
			out = append(out, Info{ControlInfo: info, Plugin: spec.Name})
		}
	}
	return out, nil
}

// TechniqueControls maps the id of each technique to the ids of the
// attack controls that name it, in catalog order.
func TechniqueControls(list []Info) map[string][]string {
	out := map[string][]string{}
	for _, c := range list {
		if c.Attack && c.Technique != "" {
			out[c.Technique] = append(out[c.Technique], c.ID)
		}
	}
	return out
}

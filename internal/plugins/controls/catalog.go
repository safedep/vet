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

// AttackIDs returns the ids of the controls that find an attack.
func AttackIDs() ([]string, error) {
	list, err := Catalog()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range list {
		if c.Attack {
			out = append(out, c.ID)
		}
	}
	return out, nil
}

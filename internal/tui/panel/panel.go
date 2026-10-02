// Package panel passes through dry/tui/panel: a titled box of fields.
package panel

import "github.com/safedep/dry/tui/panel"

// Panel is a titled box of fields.
type Panel = panel.Panel

// New returns a panel with a title.
func New(title string) *Panel { return panel.New(title) }

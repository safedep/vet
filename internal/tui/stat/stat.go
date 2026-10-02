// Package stat passes through dry/tui/stat: the summary cards.
package stat

import "github.com/safedep/dry/tui/stat"

// Card is one summary card.
type Card = stat.Card

// Render lays out the cards for the output mode.
func Render(cards ...Card) string { return stat.Render(cards...) }

package reporter

import (
	"os"

	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/text"
)

// Package reporter provides terminal color support with automatic capability detection
// and dark/light mode awareness.
//
// Color Choice Philosophy:
// For ANSI256/TrueColor terminals, this package prioritizes readability over strict
// semantic color naming. Specifically:
//   - Cyan is used instead of blue for better visibility on dark backgrounds
//   - Cyan is used instead of magenta for better contrast on dark terminals
//
// This is an intentional UX decision to address issue #537 where blue and magenta
// colors had poor visibility on dark terminal themes. The ANSI fallback still uses
// traditional blue/magenta colors with bold styling for compatibility with older terminals.

// ColorConfig holds the terminal color configuration
type ColorConfig struct {
	profile           colorprofile.Profile
	hasDarkBackground bool
}

var globalColorConfig *ColorConfig

func init() {
	globalColorConfig = &ColorConfig{
		profile:           colorprofile.Detect(os.Stdout, os.Environ()),
		hasDarkBackground: lipgloss.HasDarkBackground(),
	}
}

// GetColorConfig returns the global color configuration
func GetColorConfig() *ColorConfig {
	return globalColorConfig
}

// Semantic color functions for consistent theming
// These functions adapt colors based on terminal capability

// CriticalBgText returns text with critical severity background
func (c *ColorConfig) CriticalBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgRed, text.FgWhite, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiRed, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// CriticalText returns text with critical severity foreground
func (c *ColorConfig) CriticalText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.FgRed, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.FgHiRed.Sprint(s)
	default:
		return s
	}
}

// HighBgText returns text with high severity background
func (c *ColorConfig) HighBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgRed, text.FgWhite, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiRed, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// MediumBgText returns text with medium severity background
func (c *ColorConfig) MediumBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgYellow, text.FgBlack, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiYellow, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// LowBgText returns text with low severity background
// Note: Uses cyan instead of blue for ANSI256/TrueColor to improve visibility on dark terminals.
// Blue backgrounds have poor contrast on dark terminal themes (see issue #537).
func (c *ColorConfig) LowBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgBlue, text.FgWhite, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiCyan, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// WarningText returns text with warning color
func (c *ColorConfig) WarningText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.FgYellow, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.FgHiYellow.Sprint(s)
	default:
		return s
	}
}

// WarningBgText returns text with warning background
func (c *ColorConfig) WarningBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgYellow, text.FgBlack, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiYellow, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// SuccessBgText returns text with success background
func (c *ColorConfig) SuccessBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgGreen, text.FgBlack, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiGreen, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// InfoBgText returns text with info background
// Note: Uses cyan instead of blue for ANSI256/TrueColor to improve visibility on dark terminals.
// Blue backgrounds have poor contrast on dark terminal themes (see issue #537).
func (c *ColorConfig) InfoBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgBlue, text.FgWhite, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiCyan, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// InfoText returns text with info foreground
// Note: Uses cyan instead of blue for ANSI256/TrueColor to improve visibility on dark terminals.
// Blue text has poor contrast on dark terminal themes (see issue #537).
func (c *ColorConfig) InfoText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.FgBlue, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.FgHiCyan.Sprint(s)
	default:
		return s
	}
}

// MagentaBgText returns text with tag background
// Note: Uses cyan instead of magenta for ANSI256/TrueColor to improve visibility on dark terminals.
// Magenta/pink backgrounds have poor contrast on dark terminal themes (see issue #537).
func (c *ColorConfig) MagentaBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgMagenta, text.FgWhite, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgCyan, text.FgWhite}.Sprint(s)
	default:
		return s
	}
}

// WhiteBgText returns text with white background
func (c *ColorConfig) WhiteBgText(s string) string {
	switch c.profile {
	case colorprofile.NoTTY, colorprofile.Ascii:
		return s
	case colorprofile.ANSI:
		return text.Colors{text.BgWhite, text.FgBlack, text.Bold}.Sprint(s)
	case colorprofile.ANSI256, colorprofile.TrueColor:
		return text.Colors{text.BgHiWhite, text.FgBlack}.Sprint(s)
	default:
		return s
	}
}

// FaintText returns text with faint/dim styling
func (c *ColorConfig) FaintText(s string) string {
	if c.profile == colorprofile.NoTTY || c.profile == colorprofile.Ascii {
		return s
	}
	return text.Faint.Sprint(s)
}

// BoldText returns text with bold styling
func (c *ColorConfig) BoldText(s string) string {
	if c.profile == colorprofile.NoTTY || c.profile == colorprofile.Ascii {
		return s
	}
	return text.Bold.Sprint(s)
}

// Global convenience functions that use the global color config

// CriticalBgText returns text with critical severity background
func CriticalBgText(s string) string {
	return globalColorConfig.CriticalBgText(s)
}

// CriticalText returns text with critical severity foreground
func CriticalText(s string) string {
	return globalColorConfig.CriticalText(s)
}

// HighBgText returns text with high severity background
func HighBgText(s string) string {
	return globalColorConfig.HighBgText(s)
}

// MediumBgText returns text with medium severity background
func MediumBgText(s string) string {
	return globalColorConfig.MediumBgText(s)
}

// LowBgText returns text with low severity background
func LowBgText(s string) string {
	return globalColorConfig.LowBgText(s)
}

// WarningText returns text with warning color
func WarningText(s string) string {
	return globalColorConfig.WarningText(s)
}

// WarningBgText returns text with warning background
func WarningBgText(s string) string {
	return globalColorConfig.WarningBgText(s)
}

// SuccessBgText returns text with success background
func SuccessBgText(s string) string {
	return globalColorConfig.SuccessBgText(s)
}

// InfoBgText returns text with info background
func InfoBgText(s string) string {
	return globalColorConfig.InfoBgText(s)
}

// InfoText returns text with info foreground
func InfoText(s string) string {
	return globalColorConfig.InfoText(s)
}

// MagentaBgText returns text with magenta background
func MagentaBgText(s string) string {
	return globalColorConfig.MagentaBgText(s)
}

// WhiteBgText returns text with white background
func WhiteBgText(s string) string {
	return globalColorConfig.WhiteBgText(s)
}

// FaintText returns text with faint/dim styling
func FaintText(s string) string {
	return globalColorConfig.FaintText(s)
}

// BoldText returns text with bold styling
func BoldText(s string) string {
	return globalColorConfig.BoldText(s)
}

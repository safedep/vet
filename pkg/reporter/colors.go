package reporter

import (
	"os"

	"github.com/charmbracelet/colorprofile"
	"github.com/jedib0t/go-pretty/v6/text"
)

// colorConfig provides terminal-adaptive color configuration
type colorConfig struct {
	profile colorprofile.Profile
}

var globalColorConfig *colorConfig

func init() {
	globalColorConfig = newColorConfig()
}

// newColorConfig creates a color configuration based on terminal capabilities
func newColorConfig() *colorConfig {
	profile := colorprofile.Detect(os.Stdout, os.Environ())
	return &colorConfig{
		profile: profile,
	}
}

// getColorConfig returns the global color configuration
func getColorConfig() *colorConfig {
	return globalColorConfig
}

// Semantic color functions for different severity levels

// CriticalColor returns the color for critical severity items
func (c *colorConfig) CriticalColor() text.Colors {
	// Critical issues should be highly visible on any terminal
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256:
		// Use bright red with bold for maximum visibility
		return text.Colors{text.Bold, text.FgHiRed}
	case colorprofile.ANSI:
		// Use standard red with bold
		return text.Colors{text.Bold, text.FgRed}
	case colorprofile.Ascii, colorprofile.NoTTY:
		// Just bold, no color
		return text.Colors{text.Bold}
	default:
		return text.Colors{text.Bold, text.FgHiRed}
	}
}

// CriticalBgColor returns background color for critical items
func (c *colorConfig) CriticalBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgHiRed}
	default:
		return text.Colors{text.Bold}
	}
}

// HighColor returns the color for high severity items
func (c *colorConfig) HighColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.Bold, text.FgRed}
	default:
		return text.Colors{text.Bold}
	}
}

// HighBgColor returns background color for high severity items
func (c *colorConfig) HighBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgRed}
	default:
		return text.Colors{text.Bold}
	}
}

// MediumColor returns the color for medium severity items
func (c *colorConfig) MediumColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.FgYellow}
	default:
		return text.Colors{}
	}
}

// MediumBgColor returns background color for medium severity items
func (c *colorConfig) MediumBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgYellow}
	default:
		return text.Colors{}
	}
}

// LowColor returns the color for low severity items
func (c *colorConfig) LowColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.FgCyan}
	default:
		return text.Colors{}
	}
}

// LowBgColor returns background color for low severity items
func (c *colorConfig) LowBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgCyan}
	default:
		return text.Colors{}
	}
}

// WarningColor returns the color for warning items
func (c *colorConfig) WarningColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256:
		return text.Colors{text.FgHiYellow}
	case colorprofile.ANSI:
		return text.Colors{text.FgYellow}
	default:
		return text.Colors{}
	}
}

// SuccessColor returns the color for success/good items
func (c *colorConfig) SuccessColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.FgGreen}
	case colorprofile.Ascii, colorprofile.NoTTY:
		// Return empty Colors for terminals without color support
		return text.Colors{}
	default:
		return text.Colors{text.FgGreen}
	}
}

// SuccessBgColor returns background color for success items
func (c *colorConfig) SuccessBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgGreen}
	default:
		return text.Colors{}
	}
}

// InfoColor returns the color for informational items
func (c *colorConfig) InfoColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.FgBlue}
	default:
		return text.Colors{}
	}
}

// InfoBgColor returns background color for informational items
func (c *colorConfig) InfoBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgBlue}
	default:
		return text.Colors{}
	}
}

// ErrorBgColor returns background color for errors
func (c *colorConfig) ErrorBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgRed}
	default:
		return text.Colors{text.Bold}
	}
}

// FaintColor returns faint text for less important items
func (c *colorConfig) FaintColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.Faint}
	default:
		return text.Colors{}
	}
}

// BoldColor returns bold text
func (c *colorConfig) BoldColor() text.Colors {
	return text.Colors{text.Bold}
}

// NeutralBgColor returns a neutral background color (white)
func (c *colorConfig) NeutralBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgWhite}
	default:
		return text.Colors{}
	}
}

// MagentaBgColor returns magenta background color for special tags
func (c *colorConfig) MagentaBgColor() text.Colors {
	switch c.profile {
	case colorprofile.TrueColor, colorprofile.ANSI256, colorprofile.ANSI:
		return text.Colors{text.BgMagenta}
	default:
		return text.Colors{}
	}
}

// Convenience functions that use the global color config

// CriticalText returns critical-colored text
func CriticalText(s string) string {
	return getColorConfig().CriticalColor().Sprint(s)
}

// CriticalBgText returns critical background-colored text
func CriticalBgText(s string) string {
	return getColorConfig().CriticalBgColor().Sprint(s)
}

// HighText returns high severity colored text
func HighText(s string) string {
	return getColorConfig().HighColor().Sprint(s)
}

// HighBgText returns high severity background-colored text
func HighBgText(s string) string {
	return getColorConfig().HighBgColor().Sprint(s)
}

// MediumBgText returns medium severity background-colored text
func MediumBgText(s string) string {
	return getColorConfig().MediumBgColor().Sprint(s)
}

// LowBgText returns low severity background-colored text
func LowBgText(s string) string {
	return getColorConfig().LowBgColor().Sprint(s)
}

// WarningText returns warning-colored text
func WarningText(s string) string {
	return getColorConfig().WarningColor().Sprint(s)
}

// SuccessBgText returns success background-colored text
func SuccessBgText(s string) string {
	return getColorConfig().SuccessBgColor().Sprint(s)
}

// InfoBgText returns info background-colored text
func InfoBgText(s string) string {
	return getColorConfig().InfoBgColor().Sprint(s)
}

// ErrorBgText returns error background-colored text
func ErrorBgText(s string) string {
	return getColorConfig().ErrorBgColor().Sprint(s)
}

// FaintText returns faint-colored text
func FaintText(s string) string {
	return getColorConfig().FaintColor().Sprint(s)
}

// BoldText returns bold text
func BoldText(s string) string {
	return getColorConfig().BoldColor().Sprint(s)
}

// NeutralBgText returns neutral background-colored text
func NeutralBgText(s string) string {
	return getColorConfig().NeutralBgColor().Sprint(s)
}

// MagentaBgText returns magenta background-colored text
func MagentaBgText(s string) string {
	return getColorConfig().MagentaBgColor().Sprint(s)
}

package reporter

import (
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

// TerminalCapability represents the color capability of the terminal
type TerminalCapability int

const (
	// CapabilityNone - No color support (NO_COLOR set or not a TTY)
	CapabilityNone TerminalCapability = iota
	// CapabilityANSI - Basic 16 color ANSI support
	CapabilityANSI
	// CapabilityANSI256 - 256 color support
	CapabilityANSI256
	// CapabilityTrueColor - 24-bit true color support
	CapabilityTrueColor
)

// ColorConfig holds the terminal color configuration
type ColorConfig struct {
	capability TerminalCapability
}

var globalColorConfig *ColorConfig

func init() {
	globalColorConfig = detectTerminalCapability()
}

// detectTerminalCapability determines the color capability of the terminal
func detectTerminalCapability() *ColorConfig {
	// Respect NO_COLOR environment variable (https://no-color.org/)
	if os.Getenv("NO_COLOR") != "" {
		return &ColorConfig{capability: CapabilityNone}
	}

	// Check FORCE_COLOR for CI/CD environments
	forceColor := os.Getenv("FORCE_COLOR")
	if forceColor != "" && forceColor != "0" {
		// FORCE_COLOR set, determine level based on value
		if forceColor == "1" {
			return &ColorConfig{capability: CapabilityANSI}
		}
		if forceColor == "2" {
			return &ColorConfig{capability: CapabilityANSI256}
		}
		if forceColor == "3" {
			return &ColorConfig{capability: CapabilityTrueColor}
		}
	}

	// Check if stdout is a terminal
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return &ColorConfig{capability: CapabilityNone}
	}

	// Check COLORTERM for true color support
	colorTerm := os.Getenv("COLORTERM")
	if colorTerm == "truecolor" || colorTerm == "24bit" {
		return &ColorConfig{capability: CapabilityTrueColor}
	}

	// Check TERM environment variable
	termEnv := os.Getenv("TERM")
	if termEnv == "" {
		return &ColorConfig{capability: CapabilityANSI}
	}

	// Detect based on TERM value
	if strings.Contains(termEnv, "256color") {
		return &ColorConfig{capability: CapabilityANSI256}
	}

	if strings.Contains(termEnv, "color") || strings.HasPrefix(termEnv, "xterm") ||
		strings.HasPrefix(termEnv, "screen") || strings.HasPrefix(termEnv, "tmux") {
		return &ColorConfig{capability: CapabilityANSI}
	}

	// Default to basic ANSI colors
	return &ColorConfig{capability: CapabilityANSI}
}

// GetColorConfig returns the global color configuration
func GetColorConfig() *ColorConfig {
	return globalColorConfig
}

// Semantic color functions for consistent theming
// These functions adapt colors based on terminal capability

// CriticalBgText returns text with critical severity background (bright red with black text)
func (c *ColorConfig) CriticalBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	// Use bright red background with black text for maximum contrast
	return text.Colors{text.BgHiRed, text.FgBlack}.Sprint(s)
}

// CriticalText returns text with critical severity foreground (red)
func (c *ColorConfig) CriticalText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.FgHiRed.Sprint(s)
}

// HighBgText returns text with high severity background (bright red with black text)
func (c *ColorConfig) HighBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	// Use bright red background with black text for better contrast
	return text.Colors{text.BgHiRed, text.FgBlack}.Sprint(s)
}

// MediumBgText returns text with medium severity background (bright yellow with black text)
func (c *ColorConfig) MediumBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	// Use bright yellow background with black text for better visibility
	return text.Colors{text.BgHiYellow, text.FgBlack}.Sprint(s)
}

// LowBgText returns text with low severity background (bright cyan with black text)
func (c *ColorConfig) LowBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	// Use cyan instead of blue for better visibility on dark backgrounds
	return text.Colors{text.BgHiCyan, text.FgBlack}.Sprint(s)
}

// WarningText returns text with warning color (bright yellow)
func (c *ColorConfig) WarningText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.FgHiYellow.Sprint(s)
}

// WarningBgText returns text with warning background (bright yellow with black text)
func (c *ColorConfig) WarningBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.Colors{text.BgHiYellow, text.FgBlack}.Sprint(s)
}

// SuccessBgText returns text with success background (bright green with black text)
func (c *ColorConfig) SuccessBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.Colors{text.BgHiGreen, text.FgBlack}.Sprint(s)
}

// InfoBgText returns text with info background (bright cyan with black text)
func (c *ColorConfig) InfoBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.Colors{text.BgHiCyan, text.FgBlack}.Sprint(s)
}

// InfoText returns text with info foreground (bright cyan)
func (c *ColorConfig) InfoText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.FgHiCyan.Sprint(s)
}

// MagentaBgText returns text with cyan background (better visibility than magenta)
func (c *ColorConfig) MagentaBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	// Use cyan instead of magenta for better visibility on dark backgrounds
	return text.Colors{text.BgCyan, text.FgBlack}.Sprint(s)
}

// WhiteBgText returns text with white background and black text
func (c *ColorConfig) WhiteBgText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.Colors{text.BgHiWhite, text.FgBlack}.Sprint(s)
}

// FaintText returns text with faint/dim styling
func (c *ColorConfig) FaintText(s string) string {
	if c.capability == CapabilityNone {
		return s
	}
	return text.Faint.Sprint(s)
}

// BoldText returns text with bold styling
func (c *ColorConfig) BoldText(s string) string {
	if c.capability == CapabilityNone {
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

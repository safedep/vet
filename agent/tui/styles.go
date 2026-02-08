package tui

import "github.com/charmbracelet/lipgloss"

// ColorProfile defines semantic colors for the TUI theme.
// Swap profiles to change the entire color scheme.
type ColorProfile struct {
	Accent  lipgloss.Color // Borders, bullets
	Bright  lipgloss.Color // Titles, tool names
	Info    lipgloss.Color // Spinner, status text
	Success lipgloss.Color // Success icon/text
	Error   lipgloss.Color // Error icon/text
	Dim     lipgloss.Color // Subtitles, args, metadata
}

// DefaultProfile is the built-in purple/blue color scheme.
var DefaultProfile = ColorProfile{
	Accent:  lipgloss.Color("99"),
	Bright:  lipgloss.Color("255"),
	Info:    lipgloss.Color("39"),
	Success: lipgloss.Color("42"),
	Error:   lipgloss.Color("196"),
	Dim:     lipgloss.Color("245"),
}

// Styles holds all pre-built lipgloss styles derived from a ColorProfile.
type Styles struct {
	HeaderBox     lipgloss.Style
	Title         lipgloss.Style
	Subtitle      lipgloss.Style
	ToolBullet    lipgloss.Style
	ToolName      lipgloss.Style
	ToolArgs      lipgloss.Style
	ToolConnector lipgloss.Style
	Status        lipgloss.Style
	SuccessIcon   lipgloss.Style
	SuccessText   lipgloss.Style
	ErrorIcon     lipgloss.Style
	ErrorText     lipgloss.Style
	Meta          lipgloss.Style
	Spinner       lipgloss.Style
}

// NewStyles builds all TUI styles from the given color profile.
func NewStyles(p ColorProfile) Styles {
	return Styles{
		HeaderBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(p.Accent).
			Padding(0, 1),

		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.Bright),

		Subtitle: lipgloss.NewStyle().
			Foreground(p.Dim).
			Italic(true),

		ToolBullet: lipgloss.NewStyle().
			Foreground(p.Accent).
			SetString("● "),

		ToolName: lipgloss.NewStyle().
			Foreground(p.Bright),

		ToolArgs: lipgloss.NewStyle().
			Foreground(p.Dim).
			Italic(true),

		ToolConnector: lipgloss.NewStyle().
			Foreground(p.Dim).
			SetString("  └─ "),

		Status: lipgloss.NewStyle().
			Foreground(p.Info),

		SuccessIcon: lipgloss.NewStyle().
			Foreground(p.Success).
			Bold(true).
			SetString("✓"),

		SuccessText: lipgloss.NewStyle().
			Foreground(p.Success).
			Bold(true),

		ErrorIcon: lipgloss.NewStyle().
			Foreground(p.Error).
			Bold(true).
			SetString("✗"),

		ErrorText: lipgloss.NewStyle().
			Foreground(p.Error).
			Bold(true),

		Meta: lipgloss.NewStyle().
			Foreground(p.Dim),

		Spinner: lipgloss.NewStyle().
			Foreground(p.Info),
	}
}

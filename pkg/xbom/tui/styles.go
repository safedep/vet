package tui

import "github.com/charmbracelet/lipgloss"

// ColorProfile defines semantic colors for the xBOM TUI theme.
type ColorProfile struct {
	Accent  lipgloss.Color // Borders
	Bright  lipgloss.Color // Titles, bold text
	Info    lipgloss.Color // Spinner, counters
	Success lipgloss.Color // Success icon
	Warning lipgloss.Color // Warnings
	Dim     lipgloss.Color // Subdued text
	Bar     lipgloss.Color // Bar chart fill
}

// DefaultProfile is the built-in color scheme.
var DefaultProfile = ColorProfile{
	Accent:  lipgloss.Color("99"),
	Bright:  lipgloss.Color("255"),
	Info:    lipgloss.Color("39"),
	Success: lipgloss.Color("42"),
	Warning: lipgloss.Color("214"),
	Dim:     lipgloss.Color("245"),
	Bar:     lipgloss.Color("39"),
}

// Styles holds all pre-built lipgloss styles derived from a ColorProfile.
type Styles struct {
	SummaryBox   lipgloss.Style
	SignatureBox lipgloss.Style
	Title        lipgloss.Style
	StatLabel    lipgloss.Style
	StatValue    lipgloss.Style
	SigName      lipgloss.Style
	SigCount     lipgloss.Style
	BarFull      lipgloss.Style
	TagBadge     lipgloss.Style
	FileName     lipgloss.Style
	Counter      lipgloss.Style
	Spinner      lipgloss.Style
	SuccessIcon  lipgloss.Style
	ErrorText    lipgloss.Style
	Dim          lipgloss.Style
}

// NewStyles builds all TUI styles from the given color profile.
func NewStyles(p ColorProfile) Styles {
	return Styles{
		SummaryBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(p.Accent).
			Padding(0, 1),

		SignatureBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(p.Accent).
			Padding(0, 1),

		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.Bright),

		StatLabel: lipgloss.NewStyle().
			Foreground(p.Dim),

		StatValue: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.Bright),

		SigName: lipgloss.NewStyle().
			Foreground(p.Bright),

		SigCount: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.Info),

		BarFull: lipgloss.NewStyle().
			Foreground(p.Bar),

		TagBadge: lipgloss.NewStyle().
			Foreground(p.Bright).
			Background(p.Accent).
			Padding(0, 1),

		FileName: lipgloss.NewStyle().
			Foreground(p.Dim).
			Italic(true),

		Counter: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.Info),

		Spinner: lipgloss.NewStyle().
			Foreground(p.Info),

		SuccessIcon: lipgloss.NewStyle().
			Foreground(p.Success).
			Bold(true).
			SetString("✓"),

		ErrorText: lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true),

		Dim: lipgloss.NewStyle().
			Foreground(p.Dim),
	}
}

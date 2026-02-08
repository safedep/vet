package tui

import "github.com/charmbracelet/lipgloss"

var (
	purple = lipgloss.Color("99")
	green  = lipgloss.Color("42")
	red    = lipgloss.Color("196")
	blue   = lipgloss.Color("39")
	dim    = lipgloss.Color("245")

	headerBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(purple).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("255"))

	subtitleStyle = lipgloss.NewStyle().
			Foreground(dim).
			Italic(true)

	toolBulletStyle = lipgloss.NewStyle().
			Foreground(purple).
			SetString("● ")

	toolNameStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255"))

	toolArgsStyle = lipgloss.NewStyle().
			Foreground(dim).
			Italic(true)

	toolArgsConnector = lipgloss.NewStyle().
				Foreground(dim).
				SetString("  └─ ")

	statusStyle = lipgloss.NewStyle().
			Foreground(blue)

	successIcon = lipgloss.NewStyle().
			Foreground(green).
			Bold(true).
			SetString("✓")

	successTextStyle = lipgloss.NewStyle().
				Foreground(green).
				Bold(true)

	errorIcon = lipgloss.NewStyle().
			Foreground(red).
			Bold(true).
			SetString("✗")

	errorTextStyle = lipgloss.NewStyle().
			Foreground(red).
			Bold(true)
)

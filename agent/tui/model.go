package tui

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

// Run starts the TUI, executes the provided function, and displays progress
// until completion. It blocks until the TUI exits.
func Run(ctx context.Context, exec ExecFunc, config Config) error {
	m := newModel(ctx, exec, config)

	p := tea.NewProgram(m, tea.WithoutSignalHandler())
	// Store program reference so eventSink can Send() messages.
	// This must happen before p.Run() which triggers Init() and starts
	// the exec goroutine.
	m.program.Store(p)

	_, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	if m.err != nil {
		return m.err
	}

	return nil
}

// --- bubbletea messages ---

type toolCallMsg struct {
	name string
	args string
}

type statusMsg string

type resultMsg string

type errorMsg struct{ err error }

type execDoneMsg struct{}

// --- toolCallEntry stores a single tool invocation for display ---

type toolCallEntry struct {
	name string
	args string
}

// --- model implements tea.Model ---

type model struct {
	config    Config
	ctx       context.Context
	exec      ExecFunc
	program   atomic.Pointer[tea.Program]
	toolCalls []toolCallEntry
	status    string
	result    string
	err       error
	steps     int
	startTime time.Time
	done      bool
	spinner   spinner.Model
	width     int
}

func newModel(ctx context.Context, exec ExecFunc, config Config) *model {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(blue)

	return &model{
		config:    config,
		ctx:       ctx,
		exec:      exec,
		startTime: time.Now(),
		spinner:   s,
		width:     80,
	}
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.startExec(),
	)
}

func (m *model) startExec() tea.Cmd {
	return func() tea.Msg {
		sink := &eventSink{program: &m.program}
		err := m.exec(m.ctx, sink)
		if err != nil {
			return errorMsg{err: err}
		}
		return execDoneMsg{}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.done = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width

	case spinner.TickMsg:
		if !m.done {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}

	case toolCallMsg:
		m.steps++
		m.toolCalls = append(m.toolCalls, toolCallEntry(msg))

	case statusMsg:
		m.status = string(msg)

	case resultMsg:
		m.result = string(msg)

	case errorMsg:
		m.err = msg.err
		m.done = true
		return m, tea.Quit

	case execDoneMsg:
		m.done = true
		return m, tea.Quit
	}

	return m, nil
}

func (m *model) View() string {
	var b strings.Builder

	if !m.done {
		b.WriteString(m.viewHeader())
		b.WriteString("\n\n")
		b.WriteString(m.viewToolCalls())
		b.WriteString(m.viewSpinner())
	} else {
		b.WriteString(m.viewToolCalls())
		b.WriteString(m.viewCompletion())
		if m.result != "" {
			b.WriteString(m.viewResult())
		}
	}

	return b.String()
}

func (m *model) viewHeader() string {
	title := titleStyle.Render(m.config.Title)
	var content string
	if m.config.Subtitle != "" {
		content = title + "\n" + subtitleStyle.Render(m.config.Subtitle)
	} else {
		content = title
	}
	boxWidth := m.width - 2
	if boxWidth < 40 {
		boxWidth = 40
	}
	return headerBoxStyle.Width(boxWidth).Render(content)
}

func (m *model) viewToolCalls() string {
	if len(m.toolCalls) == 0 {
		return ""
	}

	var b strings.Builder
	maxArgLen := m.config.maxArgLen()

	for _, tc := range m.toolCalls {
		b.WriteString("  ")
		b.WriteString(toolBulletStyle.String())
		b.WriteString(toolNameStyle.Render(tc.name))
		b.WriteString("\n")

		if tc.args != "" && tc.args != "{}" {
			args := tc.args
			if len(args) > maxArgLen {
				args = args[:maxArgLen] + "…"
			}
			b.WriteString(toolArgsConnector.String())
			b.WriteString(toolArgsStyle.Render(args))
			b.WriteString("\n")
		}
	}

	return b.String()
}

func (m *model) viewSpinner() string {
	elapsed := time.Since(m.startTime).Truncate(time.Second)

	status := m.status
	if status == "" {
		status = "Working..."
	}

	meta := fmt.Sprintf("(%d steps · %s)", m.steps, elapsed)

	return fmt.Sprintf("\n  %s %s  %s\n",
		m.spinner.View(),
		statusStyle.Render(status),
		lipgloss.NewStyle().Foreground(dim).Render(meta),
	)
}

func (m *model) viewCompletion() string {
	elapsed := time.Since(m.startTime).Truncate(time.Second)

	if m.err != nil {
		return fmt.Sprintf("\n  %s %s: %s\n",
			errorIcon.String(),
			errorTextStyle.Render(fmt.Sprintf("Failed (%s, %d steps)", elapsed, m.steps)),
			m.err.Error(),
		)
	}

	return fmt.Sprintf("\n  %s %s\n",
		successIcon.String(),
		successTextStyle.Render(fmt.Sprintf("Complete (%s, %d steps)", elapsed, m.steps)),
	)
}

func (m *model) viewResult() string {
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(m.width),
		glamour.WithEmoji(),
	)
	if err != nil {
		return "\n" + m.result + "\n"
	}

	rendered, err := renderer.Render(m.result)
	if err != nil {
		return "\n" + m.result + "\n"
	}

	return "\n" + rendered
}

// --- eventSink bridges goroutine calls into bubbletea messages ---

type eventSink struct {
	program *atomic.Pointer[tea.Program]
}

func (s *eventSink) send(msg tea.Msg) {
	if s.program == nil {
		return
	}
	if p := s.program.Load(); p != nil {
		p.Send(msg)
	}
}

func (s *eventSink) ToolCall(name, args string) {
	s.send(toolCallMsg{name: name, args: args})
}

func (s *eventSink) Status(msg string) {
	s.send(statusMsg(msg))
}

func (s *eventSink) Result(content string) {
	s.send(resultMsg(content))
}

func (s *eventSink) Error(err error) {
	s.send(errorMsg{err: err})
}

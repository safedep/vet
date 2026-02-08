package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/muesli/termenv"
	"golang.org/x/term"
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

type toolCallMsg struct {
	name string
	args string
}

type statusMsg string

type resultMsg string

type thinkingMsg string

type errorMsg struct{ err error }

type renderedResultMsg string

type execDoneMsg struct{}

type toolCallEntry struct {
	name string
	args string
}

type model struct {
	config         Config
	styles         Styles
	ctx            context.Context
	exec           ExecFunc
	program        atomic.Pointer[tea.Program]
	toolCalls      []toolCallEntry
	status         string
	thinking       string
	rawResult      string
	renderedResult string
	err            error
	steps          int
	startTime      time.Time
	execDone       bool
	done           bool
	spinner        spinner.Model
	glamourStyle   string
	width          int
}

func newModel(ctx context.Context, exec ExecFunc, config Config) *model {
	profile := DefaultProfile
	if config.Profile != nil {
		profile = *config.Profile
	}

	styles := NewStyles(profile)

	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = styles.Spinner

	// Detect terminal background now, before bubbletea takes over stdin.
	// glamour.WithAutoStyle() queries the terminal via termenv which
	// deadlocks or stalls inside bubbletea's raw-mode event loop.
	glamourStyle := "dark"
	if !termenv.HasDarkBackground() {
		glamourStyle = "light"
	}

	width := 80
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}

	return &model{
		config:       config,
		styles:       styles,
		ctx:          ctx,
		exec:         exec,
		startTime:    time.Now(),
		spinner:      s,
		glamourStyle: glamourStyle,
		width:        width,
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
		if m.rawResult != "" {
			return m, m.renderResultCmd()
		}

	case spinner.TickMsg:
		if !m.done {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}

	case toolCallMsg:
		m.steps++
		m.thinking = ""
		m.toolCalls = append(m.toolCalls, toolCallEntry(msg))

	case thinkingMsg:
		m.thinking = string(msg)

	case statusMsg:
		m.status = string(msg)

	case resultMsg:
		m.thinking = ""
		m.rawResult = string(msg)
		m.status = "Rendering report..."
		return m, m.renderResultCmd()

	case renderedResultMsg:
		m.renderedResult = string(msg)
		if m.execDone {
			m.done = true
			return m, tea.Quit
		}

	case errorMsg:
		m.err = msg.err
		m.done = true
		return m, tea.Quit

	case execDoneMsg:
		m.execDone = true
		if m.rawResult == "" || m.renderedResult != "" {
			m.done = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m *model) View() string {
	var b strings.Builder

	if !m.done {
		b.WriteString(m.viewHeader())
		b.WriteString("\n\n")
		b.WriteString(m.viewToolCalls())
		b.WriteString(m.viewThinking())
		b.WriteString(m.viewSpinner())
	} else {
		b.WriteString(m.viewToolCalls())
		b.WriteString(m.viewCompletion())
		if m.rawResult != "" {
			b.WriteString(m.viewResult())
		}
	}

	return b.String()
}

func (m *model) viewHeader() string {
	title := m.styles.Title.Render(m.config.Title)
	var content string
	if m.config.Subtitle != "" {
		content = title + "\n" + m.styles.Subtitle.Render(m.config.Subtitle)
	} else {
		content = title
	}
	boxWidth := m.width - 2
	if boxWidth < 40 {
		boxWidth = 40
	}
	return m.styles.HeaderBox.Width(boxWidth).Render(content)
}

func (m *model) viewToolCalls() string {
	if len(m.toolCalls) == 0 {
		return ""
	}

	var b strings.Builder
	maxArgLen := m.config.maxArgLen()

	for _, tc := range m.toolCalls {
		b.WriteString("  ")
		b.WriteString(m.styles.ToolBullet.String())
		b.WriteString(m.styles.ToolName.Render(tc.name))
		b.WriteString("\n")

		if tc.args != "" && tc.args != "{}" {
			args := tc.args
			if len(args) > maxArgLen {
				args = args[:maxArgLen] + "…"
			}
			b.WriteString(m.styles.ToolConnector.String())
			b.WriteString(m.styles.ToolArgs.Render(args))
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
		m.styles.Status.Render(status),
		m.styles.Meta.Render(meta),
	)
}

func (m *model) viewCompletion() string {
	elapsed := time.Since(m.startTime).Truncate(time.Second)

	if m.err != nil {
		return fmt.Sprintf("\n  %s %s: %s\n",
			m.styles.ErrorIcon.String(),
			m.styles.ErrorText.Render(fmt.Sprintf("Failed (%s, %d steps)", elapsed, m.steps)),
			m.err.Error(),
		)
	}

	return fmt.Sprintf("\n  %s %s\n",
		m.styles.SuccessIcon.String(),
		m.styles.SuccessText.Render(fmt.Sprintf("Complete (%s, %d steps)", elapsed, m.steps)),
	)
}

func (m *model) renderResultCmd() tea.Cmd {
	raw := m.rawResult
	width := m.width
	style := m.glamourStyle
	return func() tea.Msg {
		renderer, err := glamour.NewTermRenderer(
			glamour.WithStylePath(style),
			glamour.WithWordWrap(width-2),
			glamour.WithEmoji(),
		)
		if err != nil {
			return renderedResultMsg(raw)
		}

		rendered, err := renderer.Render(raw)
		if err != nil {
			return renderedResultMsg(raw)
		}

		return renderedResultMsg(rendered)
	}
}

func (m *model) viewResult() string {
	if m.renderedResult != "" {
		return "\n" + m.renderedResult
	}
	return "\n" + m.rawResult + "\n"
}

func (m *model) viewThinking() string {
	if m.thinking == "" {
		return ""
	}

	line := firstLine(m.thinking)
	maxLen := m.width - 10
	if maxLen < 20 {
		maxLen = 20
	}
	if len(line) > maxLen {
		line = line[:maxLen] + "…"
	}

	return fmt.Sprintf("  %s %s\n",
		m.styles.ThinkingBullet.String(),
		m.styles.ThinkingText.Render(line))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

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

func (s *eventSink) Thinking(content string) {
	s.send(thinkingMsg(content))
}

package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

// Message types for Bubbletea updates
type statusUpdateMsg struct {
	message string
}

type agentResponseMsg struct {
	content string
}

type agentThinkingMsg struct {
	thinking bool
}

type agentToolCallMsg struct {
	toolName string
	toolArgs string
}

type thinkingTickMsg struct{}

var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Padding(0, 1)

	inputPromptStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))

	inputCursorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("255"))

	inputBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				Padding(0, 1)

	thinkingStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("33")).
			Bold(true)
)

// AgentUI represents the main TUI model
type agentUI struct {
	viewport      viewport.Model
	textInput     textarea.Model
	width         int
	height        int
	statusMessage string
	isThinking    bool
	messages      []uiMessage
	ready         bool
	agent         Agent
	session       Session
	config        AgentUIConfig
	thinkingFrame int
	inputHistory  []string
	historyIndex  int
	currentInput  string
}

// Message represents a chat message
type uiMessage struct {
	Role      string // "user", "agent", "system"
	Content   string
	Timestamp time.Time
}

// AgentUIConfig defines the configuration for the UI
type AgentUIConfig struct {
	Width                int
	Height               int
	InitialSystemMessage string
	TextInputPlaceholder string
	TitleText            string
	MaxHistory           int

	// Only for informational purposes.
	ModelName   string
	ModelVendor string
	ModelFast   bool
}

// DefaultAgentUIConfig returns the opinionated default configuration for the UI
func DefaultAgentUIConfig() AgentUIConfig {
	return AgentUIConfig{
		Width:                80,
		Height:               20,
		MaxHistory:           50,
		InitialSystemMessage: "Security Agent initialized",
		TextInputPlaceholder: "Ask me anything...",
		TitleText:            "Security Agent",
	}
}

// NewAgentUI creates a new agent UI instance
func NewAgentUI(agent Agent, session Session, config AgentUIConfig) *agentUI {
	vp := viewport.New(config.Width, config.Height)

	ta := textarea.New()
	ta.Placeholder = ""
	ta.Focus()
	ta.SetHeight(1)
	ta.SetWidth(80)
	ta.CharLimit = 1000
	ta.ShowLineNumbers = false

	ui := &agentUI{
		viewport:      vp,
		textInput:     ta,
		statusMessage: "",
		messages:      []uiMessage{},
		agent:         agent,
		session:       session,
		config:        config,
		thinkingFrame: 0,
		inputHistory:  []string{},
		historyIndex:  -1,
		currentInput:  "",
	}

	ui.addSystemMessage(config.InitialSystemMessage)

	return ui
}

// Init implements the tea.Model interface
func (m *agentUI) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		m.tickThinking(),
	)
}

// Update implements the tea.Model interface
func (m *agentUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyEnter:
			if m.textInput.Focused() && !m.isThinking {
				// Handle user input only if agent is not in thinking mode
				userInput := strings.TrimSpace(m.textInput.Value())
				if userInput != "" {
					// Add to history and reset navigation
					m.addToHistory(userInput)

					// Check if it's a slash command
					if strings.HasPrefix(userInput, "/") {
						m.addUserMessage(userInput)
						m.resetInputField()

						// Handle slash command
						cmd := m.handleSlashCommand(userInput)
						if cmd != nil {
							cmds = append(cmds, cmd)
						}
					} else {
						m.addUserMessage(userInput)
						m.resetInputField()

						// Execute agent query
						cmds = append(cmds,
							m.setThinking(true),
							m.executeAgentQuery(userInput),
						)
					}
				}
			}

		case tea.KeyTab:
			// Switch focus between input and viewport, but not while agent is thinking
			if !m.isThinking {
				if m.textInput.Focused() {
					m.textInput.Blur()
				} else {
					m.textInput.Focus()
					cmds = append(cmds, textarea.Blink)
				}
			}

		case tea.KeyUp, tea.KeyDown:
			if m.textInput.Focused() && !m.isThinking {
				// Navigate input history when text input is focused
				var direction int
				if msg.Type == tea.KeyUp {
					direction = 1 // Go back in history
				} else {
					direction = -1 // Go forward in history
				}

				historyEntry := m.navigateHistory(direction)
				m.textInput.SetValue(historyEntry)
				m.textInput.CursorEnd()
			} else if !m.textInput.Focused() {
				// Allow scrolling in viewport when not focused on text input
				m.viewport, cmd = m.viewport.Update(msg)
				cmds = append(cmds, cmd)
			}

		case tea.KeyPgUp, tea.KeyPgDown:
			// Allow scrolling in viewport when not focused on text input
			if !m.textInput.Focused() {
				m.viewport, cmd = m.viewport.Update(msg)
				cmds = append(cmds, cmd)
			}

		case tea.KeyHome:
			if !m.textInput.Focused() {
				m.viewport.GotoTop()
			}

		case tea.KeyEnd:
			if !m.textInput.Focused() {
				m.viewport.GotoBottom()
			}
		}

	case tea.WindowSizeMsg:
		// Handle window resize
		m.width = msg.Width
		m.height = msg.Height

		// Calculate dimensions for minimal UI
		headerHeight := 2 // Header + blank line
		inputHeight := 2  // Input area + status
		spacing := 1      // Bottom spacing

		// Calculate viewport dimensions to maximize output area
		viewportHeight := m.height - headerHeight - inputHeight - spacing

		// Ensure minimum height
		if viewportHeight < 10 {
			viewportHeight = 10
		}

		// Full width utilization
		viewportWidth := m.width

		// Ensure minimum width
		if viewportWidth < 50 {
			viewportWidth = 50
		}

		m.viewport.Width = viewportWidth
		m.viewport.Height = viewportHeight
		m.textInput.SetWidth(m.width - 3)

		// Update content when dimensions change
		m.viewport.SetContent(m.renderMessages())

		if !m.ready {
			m.ready = true
		}

	case statusUpdateMsg:
		m.statusMessage = msg.message

	case agentThinkingMsg:
		m.isThinking = msg.thinking

		// When agent starts thinking, blur the input
		if m.isThinking {
			m.resetInputField()
			m.textInput.Blur()
			m.thinkingFrame = 0
			cmds = append(cmds, m.tickThinking())
		} else {
			// Re-focus input when thinking stops
			m.textInput.Focus()
			cmds = append(cmds, textarea.Blink)
		}

	case agentResponseMsg:
		m.addAgentMessage(msg.content)
		cmds = append(cmds, m.setThinking(false))

	case agentToolCallMsg:
		m.addToolCallMessage(fmt.Sprintf("🔧 %s", msg.toolName), msg.toolArgs)

	case thinkingTickMsg:
		if m.isThinking {
			m.thinkingFrame = (m.thinkingFrame + 1) % 4
			cmds = append(cmds, m.tickThinking())
		}

	}

	// Update child components
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	// Only update text input if not thinking
	if !m.isThinking {
		m.textInput, cmd = m.textInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View implements the tea.Model interface
func (m *agentUI) View() string {
	if !m.ready {
		return "Loading..."
	}

	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	modelAbility := "fast"
	if !m.config.ModelFast {
		modelAbility = "slow"
	}

	modelStatusLine := fmt.Sprintf("%s/%s (%s)", m.config.ModelVendor, m.config.ModelName, modelAbility)

	header := headerStyle.Render(fmt.Sprintf("%s %s", m.config.TitleText, modelStatusLine))

	content := m.viewport.View()

	var thinkingIndicator string
	if m.isThinking {
		thinkingFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		spinner := thinkingFrames[m.thinkingFrame%len(thinkingFrames)]
		thinkingIndicator = thinkingStyle.Render(fmt.Sprintf("%s thinking...", spinner))
	}

	var inputArea string
	userInput := m.textInput.Value()
	cursor := ""
	if m.textInput.Focused() && !m.isThinking {
		cursor = inputCursorStyle.Render("▊")
	}

	inputContent := fmt.Sprintf("%s%s%s", inputPromptStyle.Render("> "), userInput, cursor)
	inputArea = inputBorderStyle.Width(m.width - 2).Render(inputContent)

	statusLine := inputPromptStyle.Render(fmt.Sprintf("** %s | ctrl+c to exit", modelStatusLine))

	var components []string
	components = append(components, header, "", content, "")

	if thinkingIndicator != "" {
		components = append(components, thinkingIndicator)
	}

	components = append(components, inputArea, statusLine)

	return lipgloss.JoinVertical(lipgloss.Left, components...)
}

func (m *agentUI) resetInputField() {
	m.textInput.Reset()
	m.textInput.SetValue("")
	m.textInput.CursorStart()
}

func (m *agentUI) addUserMessage(content string) {
	m.messages = append(m.messages, uiMessage{
		Role:      "user",
		Content:   content,
		Timestamp: time.Now(),
	})

	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *agentUI) addAgentMessage(content string) {
	m.messages = append(m.messages, uiMessage{
		Role:      "agent",
		Content:   content,
		Timestamp: time.Now(),
	})

	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *agentUI) addSystemMessage(content string) {
	m.messages = append(m.messages, uiMessage{
		Role:      "system",
		Content:   content,
		Timestamp: time.Now(),
	})

	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *agentUI) addToolCallMessage(toolName string, toolArgs string) {
	content := fmt.Sprintf("    %s", toolName)
	if toolArgs != "" && toolArgs != "{}" {
		content += fmt.Sprintf("\n    └─ %s", toolArgs)
	}

	m.messages = append(m.messages, uiMessage{
		Role:      "tool",
		Content:   content,
		Timestamp: time.Now(),
	})

	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

// renderMessages formats all messages for display
func (m *agentUI) renderMessages() string {
	var rendered []string

	rendered = append(rendered, "", "")

	contentWidth := m.viewport.Width - 2 // Account for internal padding
	if contentWidth < 40 {
		contentWidth = 40
	}

	r, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle("notty"),
		glamour.WithWordWrap(contentWidth),
	)
	if err != nil {
		r = nil
	}

	for _, msg := range m.messages {
		timestamp := msg.Timestamp.Format("15:04:05")

		switch msg.Role {
		case "user":
			userHeaderStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("86")).
				Bold(true).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color("86")).
				Padding(0, 1)

			userContentStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("255")).
				Padding(0, 2)

			rendered = append(rendered,
				userHeaderStyle.Render(fmt.Sprintf("[%s] → You:", timestamp)),
				userContentStyle.Render(msg.Content),
				"",
			)
		case "agent":
			var content string
			if r != nil {
				renderedMarkdown, err := r.Render(msg.Content)
				if err == nil {
					content = strings.TrimSpace(renderedMarkdown)
				} else {
					content = msg.Content // Fallback to plain text
				}
			} else {
				content = msg.Content
			}

			agentHeaderStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("39")).
				Bold(true).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color("39")).
				Padding(0, 1)

			agentContentStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("255")).
				Padding(0, 2)

			rendered = append(rendered,
				agentHeaderStyle.Render(fmt.Sprintf("[%s] ← Agent:", timestamp)),
				agentContentStyle.Render(content),
				"",
			)
		case "system":
			systemStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("241")).
				Italic(true).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color("241")).
				Padding(0, 1)

			rendered = append(rendered,
				systemStyle.Render(fmt.Sprintf("[%s] ℹ %s", timestamp, msg.Content)),
				"",
			)
		case "tool":
			toolStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("245")).
				Italic(true).
				Faint(true).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color("245")).
				Padding(0, 1)

			rendered = append(rendered,
				toolStyle.Render(fmt.Sprintf("[%s] %s", timestamp, msg.Content)),
				"",
			)
		}
	}

	rendered = append(rendered, "", "")

	return strings.Join(rendered, "\n")
}

func (m *agentUI) updateStatus(message string) tea.Cmd {
	return func() tea.Msg {
		return statusUpdateMsg{message: message}
	}
}

func (m *agentUI) setThinking(thinking bool) tea.Cmd {
	return func() tea.Msg {
		return agentThinkingMsg{thinking: thinking}
	}
}

func (m *agentUI) executeAgentQuery(userInput string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		input := Input{
			Query: userInput,
		}

		toolCallHook := func(_ context.Context, _ Session, _ Input, toolName string, toolArgs string) error {
			m.Update(agentToolCallMsg{toolName: toolName, toolArgs: toolArgs})
			return nil
		}

		output, err := m.agent.Execute(ctx, m.session, input, WithToolCallHook(toolCallHook))
		if err != nil {
			return agentResponseMsg{
				content: fmt.Sprintf("❌ **Error**\n\nSorry, I encountered an error while processing your query:\n\n%s", err.Error()),
			}
		}

		return agentResponseMsg{content: output.Answer}
	}
}

// StartUI starts the TUI application with the default configuration
func StartUI(agent Agent, session Session) error {
	config := DefaultAgentUIConfig()
	config.InitialSystemMessage = ""
	return StartUIWithConfig(agent, session, config)
}

// StartUIWithConfig starts the TUI application with the provided configuration
func StartUIWithConfig(agent Agent, session Session, config AgentUIConfig) error {
	ui := NewAgentUI(agent, session, config)

	p := tea.NewProgram(
		ui,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	_, err := p.Run()
	return err
}

func (m *agentUI) tickThinking() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(time.Time) tea.Msg {
		return thinkingTickMsg{}
	})
}

// handleSlashCommand processes commands that start with '/'
func (m *agentUI) handleSlashCommand(command string) tea.Cmd {
	switch command {
	case "/exit":
		m.addSystemMessage("Goodbye! Exiting gracefully...")
		return tea.Quit
	default:
		m.addSystemMessage(fmt.Sprintf("Unknown command: %s", command))
		return nil
	}
}

// addToHistory adds input to history buffer with a maximum of 50 entries
func (m *agentUI) addToHistory(input string) {
	// Don't add empty strings or duplicates of the last entry
	if input == "" || (len(m.inputHistory) > 0 && m.inputHistory[len(m.inputHistory)-1] == input) {
		return
	}

	m.inputHistory = append(m.inputHistory, input)

	// Keep only the last maxHistory entries
	if len(m.inputHistory) > m.config.MaxHistory {
		m.inputHistory = m.inputHistory[len(m.inputHistory)-m.config.MaxHistory:]
	}

	// Reset history navigation
	m.historyIndex = -1
	m.currentInput = ""
}

// navigateHistory moves through input history and returns the selected entry
func (m *agentUI) navigateHistory(direction int) string {
	if len(m.inputHistory) == 0 {
		return ""
	}

	// Save current input when starting navigation
	if m.historyIndex == -1 {
		m.currentInput = m.textInput.Value()
	}

	// Calculate new index
	newIndex := m.historyIndex + direction

	// Handle boundaries
	if newIndex < -1 {
		newIndex = -1
	} else if newIndex >= len(m.inputHistory) {
		newIndex = len(m.inputHistory) - 1
	}

	m.historyIndex = newIndex

	// Return the appropriate entry
	if m.historyIndex == -1 {
		return m.currentInput
	}

	return m.inputHistory[len(m.inputHistory)-1-m.historyIndex]
}

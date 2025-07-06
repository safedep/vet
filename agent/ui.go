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

// Styles using Lipgloss
var (
	// Main panel styles
	mainPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(1, 2)

	// Chat input styles
	inputPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

	// Disabled input styles
	inputPanelDisabledStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("238")).
				Foreground(lipgloss.Color("243")).
				Padding(0, 1)

	// Status bar styles
	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("62")).
			Foreground(lipgloss.Color("230")).
			Padding(0, 1)

	// Message styles
	userMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("86")).
				Bold(true)

	agentMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("39"))

	systemMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("241")).
				Italic(true)

	// Thinking indicator style
	thinkingStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Italic(true)
)

// AgentUI represents the main TUI model
type AgentUI struct {
	viewport      viewport.Model
	textInput     textarea.Model
	width         int
	height        int
	statusMessage string
	isThinking    bool
	messages      []Message
	ready         bool
	agent         Agent
	session       Session
}

// Message represents a chat message
type Message struct {
	Role      string // "user", "agent", "system"
	Content   string
	Timestamp time.Time
}

// NewAgentUI creates a new agent UI instance
func NewAgentUI(agent Agent, session Session) *AgentUI {
	// Create viewport for main content
	vp := viewport.New(80, 20)
	vp.Style = mainPanelStyle

	// Create text input for chat
	ta := textarea.New()
	ta.Placeholder = "Ask me anything about your security data..."
	ta.Focus()
	ta.SetHeight(3)
	ta.SetWidth(80)

	ui := &AgentUI{
		viewport:      vp,
		textInput:     ta,
		statusMessage: "Initializing agent...",
		messages:      []Message{},
		agent:         agent,
		session:       session,
	}

	// Add welcome message
	ui.addSystemMessage("🤖 Security Agent initialized. Ask me anything about your dependencies, vulnerabilities, or supply chain risks.")

	return ui
}

// Init implements the tea.Model interface
func (m *AgentUI) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		m.updateStatus("Ready - Ask me anything!"),
	)
}

// Update implements the tea.Model interface
func (m *AgentUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyEnter:
			if m.textInput.Focused() && !m.isThinking {
				// Handle user input only if agent is not thinking
				userInput := strings.TrimSpace(m.textInput.Value())
				if userInput != "" {
					m.addUserMessage(userInput)
					m.textInput.Reset()

					// Execute agent query
					cmds = append(cmds,
						m.updateStatus("Agent is analyzing your question..."),
						m.setThinking(true),
						m.executeAgentQuery(userInput),
					)
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

		case tea.KeyUp, tea.KeyDown, tea.KeyPgUp, tea.KeyPgDown:
			// Allow scrolling in viewport when not focused on text input
			if !m.textInput.Focused() {
				m.viewport, cmd = m.viewport.Update(msg)
				cmds = append(cmds, cmd)
			}

		case tea.KeyHome:
			// Go to top of viewport
			if !m.textInput.Focused() {
				m.viewport.GotoTop()
			}

		case tea.KeyEnd:
			// Go to bottom of viewport
			if !m.textInput.Focused() {
				m.viewport.GotoBottom()
			}
		}

	case tea.WindowSizeMsg:
		// Handle window resize
		m.width = msg.Width
		m.height = msg.Height

		// Calculate dimensions more accurately
		headerHeight := 3 // Header with padding and spacing
		helpHeight := 1   // Help text line
		statusHeight := 1 // Status bar
		inputHeight := 7  // Text input area with borders and padding

		// Account for main panel borders and padding (2 lines for borders + 2 lines for padding)
		mainPanelDecorations := 4

		// Calculate viewport dimensions
		viewportHeight := m.height - headerHeight - helpHeight - statusHeight - inputHeight - mainPanelDecorations

		// Ensure minimum height
		if viewportHeight < 8 {
			viewportHeight = 8
		}

		// Account for main panel padding (4 characters total: 2 left + 2 right)
		viewportWidth := m.width - 8

		// Ensure minimum width
		if viewportWidth < 40 {
			viewportWidth = 40
		}

		m.viewport.Width = viewportWidth
		m.viewport.Height = viewportHeight
		m.textInput.SetWidth(m.width - 4)

		// Update content when dimensions change
		m.viewport.SetContent(m.renderMessages())

		if !m.ready {
			m.ready = true
		}

	case statusUpdateMsg:
		m.statusMessage = msg.message

	case agentThinkingMsg:
		m.isThinking = msg.thinking
		// When agent starts thinking, blur the input and update placeholder
		if m.isThinking {
			m.textInput.Blur()
			m.textInput.Placeholder = "Please wait while agent is responding..."
		} else {
			// Re-focus input when thinking stops and restore placeholder
			m.textInput.Placeholder = "Ask me anything about your security data..."
			m.textInput.Focus()
			cmds = append(cmds, textarea.Blink)
		}

	case agentResponseMsg:
		m.addAgentMessage(msg.content)
		cmds = append(cmds,
			m.setThinking(false),
			m.updateStatus("Ready - Ask me anything!"),
		)
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
func (m *AgentUI) View() string {
	if !m.ready {
		return "Loading..."
	}

	// Calculate available space properly
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	// Header - make it more prominent
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("62")).
		Background(lipgloss.Color("235")).
		Align(lipgloss.Center).
		Width(m.width).
		Padding(1, 1)

	header := headerStyle.Render("🔍 vet Query Agent - Interactive Query Mode")

	// Main viewport with messages - use exact viewport dimensions
	mainPanel := mainPanelStyle.
		Width(m.width - 4).
		Render(m.viewport.View())

	// Input panel - style based on thinking state
	var inputPanel string
	if m.isThinking {
		// Use disabled style when agent is thinking
		inputPanel = inputPanelDisabledStyle.
			Width(m.width - 4).
			Render(m.textInput.View())
	} else {
		// Use normal style when ready for input
		inputPanel = inputPanelStyle.
			Width(m.width - 4).
			Render(m.textInput.View())
	}

	// Help text - update based on thinking state
	var helpContent string
	if m.isThinking {
		helpContent = "Agent is responding... • ↑↓/PgUp/PgDown: Scroll • Home/End: Top/Bottom • Ctrl+C/Esc: Quit"
	} else {
		helpContent = "Tab: Switch focus • Enter: Send message • ↑↓/PgUp/PgDown: Scroll • Home/End: Top/Bottom • Ctrl+C/Esc: Quit"
	}

	helpText := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Align(lipgloss.Center).
		Width(m.width).
		Render(helpContent)

	// Status bar
	statusContent := m.statusMessage
	if m.isThinking {
		statusContent = thinkingStyle.Render("🤔 Agent is thinking...") + " " + statusContent
	}

	statusBar := statusBarStyle.
		Width(m.width).
		Render(statusContent)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		mainPanel,
		inputPanel,
		helpText,
		statusBar,
	)
}

// Helper methods for message management
func (m *AgentUI) addUserMessage(content string) {
	m.messages = append(m.messages, Message{
		Role:      "user",
		Content:   content,
		Timestamp: time.Now(),
	})
	// Update viewport content and scroll to bottom
	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *AgentUI) addAgentMessage(content string) {
	m.messages = append(m.messages, Message{
		Role:      "agent",
		Content:   content,
		Timestamp: time.Now(),
	})
	// Update viewport content and scroll to bottom
	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *AgentUI) addSystemMessage(content string) {
	m.messages = append(m.messages, Message{
		Role:      "system",
		Content:   content,
		Timestamp: time.Now(),
	})
	// Update viewport content and scroll to bottom
	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

// renderMessages formats all messages for display
func (m *AgentUI) renderMessages() string {
	var rendered []string

	// Add adequate top spacing to prevent text cutoff
	rendered = append(rendered, "", "")

	// Calculate proper width for content, accounting for main panel padding
	contentWidth := m.viewport.Width - 2 // Account for internal padding
	if contentWidth < 40 {
		contentWidth = 40
	}

	// Create a glamour renderer for markdown with proper width
	r, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(contentWidth),
	)
	if err != nil {
		// Fallback to plain text if glamour fails
		r = nil
	}

	for _, msg := range m.messages {
		timestamp := msg.Timestamp.Format("15:04:05")

		switch msg.Role {
		case "user":
			rendered = append(rendered,
				userMessageStyle.Render(fmt.Sprintf("[%s] You:", timestamp)),
				msg.Content,
				"",
			)
		case "agent":
			// Use glamour to render markdown for agent messages
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

			rendered = append(rendered,
				agentMessageStyle.Render(fmt.Sprintf("[%s] Agent:", timestamp)),
				content,
				"",
			)
		case "system":
			rendered = append(rendered,
				systemMessageStyle.Render(fmt.Sprintf("[%s] %s", timestamp, msg.Content)),
				"",
			)
		}
	}

	// Add bottom spacing for better scrolling
	rendered = append(rendered, "", "")

	return strings.Join(rendered, "\n")
}

// Command creators for Bubbletea
func (m *AgentUI) updateStatus(message string) tea.Cmd {
	return func() tea.Msg {
		return statusUpdateMsg{message: message}
	}
}

func (m *AgentUI) setThinking(thinking bool) tea.Cmd {
	return func() tea.Msg {
		return agentThinkingMsg{thinking: thinking}
	}
}

// executeAgentQuery executes a query using the agent interface
func (m *AgentUI) executeAgentQuery(userInput string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		input := Input{
			Query: userInput,
		}

		output, err := m.agent.Execute(ctx, m.session, input)
		if err != nil {
			return agentResponseMsg{
				content: fmt.Sprintf("❌ **Error**\n\nSorry, I encountered an error while processing your query:\n\n%s", err.Error()),
			}
		}

		return agentResponseMsg{content: output.Answer}
	}
}

// RunAgentUI starts the TUI application
func RunAgentUI(agent Agent, session Session) error {
	ui := NewAgentUI(agent, session)

	p := tea.NewProgram(
		ui,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	_, err := p.Run()
	return err
}

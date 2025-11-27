package agent

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func TestAgentUICreation(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	assert.NotNil(t, ui, "Failed to create AgentUI")
	assert.Empty(t, ui.statusMessage, "Expected empty status message")
	assert.False(t, ui.isThinking, "UI should not be thinking initially")
	assert.Equal(t, 0, ui.thinkingFrame, "Thinking frame should be 0 initially")

	// Check that system message was added if config has one
	if config.InitialSystemMessage != "" {
		assert.NotEmpty(t, ui.messages, "Expected system message to be added if InitialSystemMessage is set")
	}
}

func TestDefaultAgentUIConfig(t *testing.T) {
	config := DefaultAgentUIConfig()

	assert.Equal(t, 80, config.Width, "Expected default width 80")
	assert.Equal(t, 20, config.Height, "Expected default height 20")
	assert.Equal(t, "Security Agent", config.TitleText, "Expected title 'Security Agent'")
	assert.Equal(t, "Ask me anything...", config.TextInputPlaceholder, "Expected placeholder 'Ask me anything...'")
}

func TestMessageManagement(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	initialCount := len(ui.messages)

	// Test adding user message
	ui.addUserMessage("Test user message")
	assert.Equal(t, initialCount+1, len(ui.messages), "Expected message count to increase")

	lastMessage := ui.messages[len(ui.messages)-1]
	assert.Equal(t, "user", lastMessage.Role, "Expected last message role to be 'user'")
	assert.Equal(t, "Test user message", lastMessage.Content, "Expected last message content to be 'Test user message'")

	// Test adding agent message
	ui.addAgentMessage("Test agent response")
	assert.Equal(t, initialCount+2, len(ui.messages), "Expected message count to increase")

	lastMessage = ui.messages[len(ui.messages)-1]
	assert.Equal(t, "agent", lastMessage.Role, "Expected last message role to be 'agent'")

	// Test adding system message
	ui.addSystemMessage("System notification")
	assert.Equal(t, initialCount+3, len(ui.messages), "Expected message count to increase")

	lastMessage = ui.messages[len(ui.messages)-1]
	assert.Equal(t, "system", lastMessage.Role, "Expected last message role to be 'system'")

	// Test adding tool call message
	ui.addToolCallMessage("ScanVulnerabilities", `{"path": "/app"}`)
	assert.Equal(t, initialCount+4, len(ui.messages), "Expected message count to increase")

	lastMessage = ui.messages[len(ui.messages)-1]
	assert.Equal(t, "tool", lastMessage.Role, "Expected last message role to be 'tool'")
}

func TestMessageRendering(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Set up viewport dimensions for rendering
	ui.viewport.Width = 80
	ui.viewport.Height = 20

	ui.addUserMessage("How many vulnerabilities?")
	ui.addAgentMessage("Found 5 critical vulnerabilities")

	rendered := ui.renderMessages()

	assert.NotEmpty(t, rendered, "Expected non-empty rendered output")
	assert.Contains(t, rendered, "How many vulnerabilities?", "Rendered output should contain user message")
	assert.Contains(t, rendered, "Found 5 critical vulnerabilities", "Rendered output should contain agent message")
	assert.Contains(t, rendered, "You:", "Rendered output should contain user label")
	assert.Contains(t, rendered, "Agent:", "Rendered output should contain agent label")
}

func TestViewportDimensions(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Test window resize handling
	resizeMsg := tea.WindowSizeMsg{Width: 100, Height: 30}
	ui.Update(resizeMsg)

	assert.Equal(t, 100, ui.width, "Expected width 100")
	assert.Equal(t, 30, ui.height, "Expected height 30")

	// Test minimum dimensions enforcement
	resizeMsg = tea.WindowSizeMsg{Width: 10, Height: 5}
	ui.Update(resizeMsg)

	assert.GreaterOrEqual(t, ui.viewport.Width, 50, "Viewport width should be enforced to minimum 50")
	assert.GreaterOrEqual(t, ui.viewport.Height, 10, "Viewport height should be enforced to minimum 10")
}

func TestViewRendering(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	config.ModelName = "gpt-4"
	config.ModelVendor = "openai"
	config.ModelFast = false

	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.width = 80
	ui.height = 24
	ui.ready = true

	view := ui.View()

	assert.Contains(t, view, "Security Agent", "View should contain title")
	assert.Contains(t, view, "openai/gpt-4", "View should contain model information")
	assert.Contains(t, view, ">", "View should contain input prompt")
	assert.Contains(t, view, "ctrl+c to exit", "View should contain exit instruction")
}

func TestThinkingState(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.width = 80
	ui.height = 24
	ui.ready = true

	// Initially not thinking
	assert.False(t, ui.isThinking, "UI should not be thinking initially")

	// Set thinking state
	thinkingMsg := agentThinkingMsg{thinking: true}
	ui.Update(thinkingMsg)

	assert.True(t, ui.isThinking, "UI should be thinking after agentThinkingMsg")

	// Check view contains thinking indicator
	view := ui.View()
	assert.Contains(t, view, "thinking...", "View should contain thinking indicator when thinking")

	// Stop thinking
	thinkingMsg = agentThinkingMsg{thinking: false}
	ui.Update(thinkingMsg)

	assert.False(t, ui.isThinking, "UI should not be thinking after agentThinkingMsg with false")
}

func TestKeyboardHandling(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.width = 80
	ui.height = 24
	ui.ready = true

	var keyMsg tea.KeyMsg
	var model tea.Model
	var cmd tea.Cmd

	// Test Ctrl+C exits immediately
	keyMsg = tea.KeyMsg{Type: tea.KeyCtrlC}
	_, cmd = ui.Update(keyMsg)

	assert.NotNil(t, cmd, "Ctrl+C should return quit command")

	// Test Tab key for focus switching when not thinking
	ui.textInput.Focus()
	keyMsg = tea.KeyMsg{Type: tea.KeyTab}
	model, _ = ui.Update(keyMsg)
	ui = model.(*agentUI)

	assert.False(t, ui.textInput.Focused(), "Tab should blur text input when it's focused")

	// Test Enter key handling when not thinking
	ui.textInput.Focus()
	ui.textInput.SetValue("test message")
	initialMessageCount := len(ui.messages)

	keyMsg = tea.KeyMsg{Type: tea.KeyEnter}
	model, _ = ui.Update(keyMsg)
	ui = model.(*agentUI)

	assert.Equal(t, initialMessageCount+1, len(ui.messages), "Enter should add user message when input is not empty")

	// Note: Input field reset happens when thinking starts, not immediately
	// The resetInputField() is called, but the UI state may not reflect it immediately in tests
}

func TestInputFieldReset(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Set some input text
	ui.textInput.SetValue("test input")
	assert.Equal(t, "test input", ui.textInput.Value(), "Input should contain test text")

	// Reset input field
	ui.resetInputField()
	assert.Empty(t, ui.textInput.Value(), "Input should be empty after reset")
}

func TestCommandCreation(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Test status update command
	cmd := ui.updateStatus("Testing status")
	assert.NotNil(t, cmd, "updateStatus should return a non-nil command")

	// Test thinking command
	cmd = ui.setThinking(true)
	assert.NotNil(t, cmd, "setThinking should return a non-nil command")

	// Test execute agent query command
	cmd = ui.executeAgentQuery("test query")
	assert.NotNil(t, cmd, "executeAgentQuery should return a non-nil command")
}

func TestMessageTimestamps(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	before := time.Now()
	ui.addUserMessage("Test message")
	after := time.Now()

	message := ui.messages[len(ui.messages)-1]

	assert.True(t, message.Timestamp.After(before) || message.Timestamp.Equal(before), "Message timestamp should be after or equal to before time")
	assert.True(t, message.Timestamp.Before(after) || message.Timestamp.Equal(after), "Message timestamp should be before or equal to after time")
}

func TestUIInitialization(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Test Init command
	cmd := ui.Init()
	assert.NotNil(t, cmd, "Init should return a non-nil command")

	// Test initial state before ready
	view := ui.View()
	assert.Equal(t, "Loading...", view, "View should show loading before ready")

	// Test with zero dimensions
	ui.ready = true
	ui.width = 0
	ui.height = 0
	view = ui.View()
	assert.Equal(t, "Initializing...", view, "View should show initializing with zero dimensions")
}

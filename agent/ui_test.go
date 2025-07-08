package agent

import (
	"testing"
	"time"
)

func TestAgentUICreation(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	if ui == nil {
		t.Fatal("Failed to create AgentUI")
	}

	if ui.statusMessage != "Initializing agent..." {
		t.Errorf("Expected status message 'Initializing agent...', got '%s'", ui.statusMessage)
	}

	if len(ui.messages) != 1 {
		t.Errorf("Expected 1 initial message, got %d", len(ui.messages))
	}

	if ui.messages[0].Role != "system" {
		t.Errorf("Expected first message to be 'system', got '%s'", ui.messages[0].Role)
	}
}

func TestMessageManagement(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Test adding user message
	ui.addUserMessage("Test user message")

	if len(ui.messages) != 2 { // Initial system message + user message
		t.Errorf("Expected 2 messages, got %d", len(ui.messages))
	}

	lastMessage := ui.messages[len(ui.messages)-1]
	if lastMessage.Role != "user" {
		t.Errorf("Expected last message role to be 'user', got '%s'", lastMessage.Role)
	}

	if lastMessage.Content != "Test user message" {
		t.Errorf("Expected last message content to be 'Test user message', got '%s'", lastMessage.Content)
	}

	// Test adding agent message
	ui.addAgentMessage("Test agent response")

	if len(ui.messages) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(ui.messages))
	}

	lastMessage = ui.messages[len(ui.messages)-1]
	if lastMessage.Role != "agent" {
		t.Errorf("Expected last message role to be 'agent', got '%s'", lastMessage.Role)
	}
}

func TestMessageRendering(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.addUserMessage("How many vulnerabilities?")
	ui.addAgentMessage("Found 5 critical vulnerabilities")

	rendered := ui.renderMessages()

	if rendered == "" {
		t.Error("Expected non-empty rendered output")
	}

	// Check that messages contain expected content
	if !contains(rendered, "How many vulnerabilities?") {
		t.Error("Rendered output should contain user message")
	}

	if !contains(rendered, "Found 5 critical vulnerabilities") {
		t.Error("Rendered output should contain agent message")
	}

	if !contains(rendered, "You:") {
		t.Error("Rendered output should contain user label")
	}

	if !contains(rendered, "Agent:") {
		t.Error("Rendered output should contain agent label")
	}
}

func TestViewportUpdates(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Set some dimensions to make viewport functional
	ui.width = 80
	ui.height = 24
	ui.ready = true

	// Check that messages are being added properly
	initialMessageCount := len(ui.messages)

	// Add a message
	ui.addUserMessage("Test message")

	if len(ui.messages) != initialMessageCount+1 {
		t.Error("Message should be added to messages slice")
	}

	// Check that the message content is correct
	lastMessage := ui.messages[len(ui.messages)-1]
	if lastMessage.Content != "Test message" {
		t.Error("Added message should have correct content")
	}

	// Check that viewport is updated by rendering the messages
	rendered := ui.renderMessages()
	if !contains(rendered, "Test message") {
		t.Error("Rendered content should contain the new message")
	}
}

func TestHeaderVisibility(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.width = 80
	ui.height = 24
	ui.ready = true

	view := ui.View()

	if !contains(view, "vet Query Agent") {
		t.Error("Header should be visible in the view")
	}

	if !contains(view, "🔍") {
		t.Error("Header icon should be visible")
	}
}

func TestInputDisabling(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.width = 80
	ui.height = 24
	ui.ready = true

	// Initially not thinking
	if ui.isThinking {
		t.Error("UI should not be thinking initially")
	}

	// Check initial placeholder
	if ui.textInput.Placeholder != "Ask me anything about your security data..." {
		t.Error("Initial placeholder should be the normal prompt")
	}

	// Set thinking state
	ui.isThinking = true
	msg := agentThinkingMsg{thinking: true}
	ui.Update(msg)

	// Check that placeholder changed
	if ui.textInput.Placeholder != "Please wait while agent is responding..." {
		t.Error("Placeholder should change when thinking")
	}

	// Set not thinking
	ui.isThinking = false
	msg = agentThinkingMsg{thinking: false}
	ui.Update(msg)

	// Check that placeholder restored
	if ui.textInput.Placeholder != "Ask me anything about your security data..." {
		t.Error("Placeholder should restore when not thinking")
	}
}

func TestInputStateInView(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)
	ui.width = 80
	ui.height = 24
	ui.ready = true

	// Test normal state
	view := ui.View()
	if !contains(view, "Enter: Send message") {
		t.Error("Help text should show send message when not thinking")
	}

	// Test thinking state
	ui.isThinking = true
	view = ui.View()
	if !contains(view, "Agent is responding...") {
		t.Error("Help text should show agent responding when thinking")
	}

	if contains(view, "Enter: Send message") {
		t.Error("Help text should not show send message when thinking")
	}
}

func TestCommandCreation(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Test status update command
	cmd := ui.updateStatus("Testing status")
	if cmd == nil {
		t.Error("updateStatus should return a non-nil command")
	}

	// Test thinking command
	cmd = ui.setThinking(true)
	if cmd == nil {
		t.Error("setThinking should return a non-nil command")
	}
}

func TestExecuteAgentQuery(t *testing.T) {
	mockAgent := NewMockAgent()
	mockSession := NewMockSession()
	config := DefaultAgentUIConfig()
	ui := NewAgentUI(mockAgent, mockSession, config)

	// Test vulnerability query response
	cmd := ui.executeAgentQuery("How many vulnerabilities?")
	if cmd == nil {
		t.Error("executeAgentQuery should return a non-nil command")
	}

	// Test malware query response
	cmd = ui.executeAgentQuery("Check for malware")
	if cmd == nil {
		t.Error("executeAgentQuery should return a non-nil command")
	}

	// Test general query response
	cmd = ui.executeAgentQuery("General security question")
	if cmd == nil {
		t.Error("executeAgentQuery should return a non-nil command")
	}
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

	if message.Timestamp.Before(before) || message.Timestamp.After(after) {
		t.Error("Message timestamp should be between before and after times")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr))))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

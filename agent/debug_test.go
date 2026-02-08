package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMessages() []*schema.Message {
	return []*schema.Message{
		{
			Role:    schema.System,
			Content: "You are a helpful assistant.",
		},
		{
			Role:    schema.User,
			Content: "Hello, what tools do you have?",
		},
		{
			Role:    schema.Assistant,
			Content: "I can help with that.",
			ToolCalls: []schema.ToolCall{
				{
					ID:   "call_1",
					Type: "function",
					Function: schema.FunctionCall{
						Name:      "search",
						Arguments: `{"query": "test"}`,
					},
				},
			},
		},
		{
			Role:       schema.Tool,
			Content:    `{"results": ["item1"]}`,
			ToolCallID: "call_1",
			ToolName:   "search",
		},
	}
}

func TestDebugPromptDumper_WritesFiles(t *testing.T) {
	dir := t.TempDir()

	a := &reactQueryAgent{id: "test-agent-id"}
	dumper := a.newDebugPromptDumper(dir)

	msgs := testMessages()

	dumper(context.Background(), msgs)
	dumper(context.Background(), msgs)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	assert.Equal(t, "prompt-test-agent-id-0001.md", entries[0].Name())
	assert.Equal(t, "prompt-test-agent-id-0002.md", entries[1].Name())

	content, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	require.NoError(t, err)

	s := string(content)
	assert.Contains(t, s, "# Agent Prompt - Step 1")
	assert.Contains(t, s, "**Agent ID:** test-agent-id")
	assert.Contains(t, s, "[system]")
	assert.Contains(t, s, "[user]")
	assert.Contains(t, s, "[assistant]")
	assert.Contains(t, s, "[tool]")
	assert.Contains(t, s, "You are a helpful assistant.")
	assert.Contains(t, s, "### Tool Calls")
	assert.Contains(t, s, "search")
}

func TestDebugPromptDumper_StepCounterIncrements(t *testing.T) {
	dir := t.TempDir()

	a := &reactQueryAgent{id: "step-test"}
	dumper := a.newDebugPromptDumper(dir)

	msgs := []*schema.Message{{Role: schema.User, Content: "hi"}}

	for i := 0; i < 5; i++ {
		dumper(context.Background(), msgs)
	}

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	expectedNames := []string{
		"prompt-step-test-0001.md",
		"prompt-step-test-0002.md",
		"prompt-step-test-0003.md",
		"prompt-step-test-0004.md",
		"prompt-step-test-0005.md",
	}
	for i, entry := range entries {
		assert.Equal(t, expectedNames[i], entry.Name())
	}
}

func TestDebugPromptDumper_ReturnMessagesUnchanged(t *testing.T) {
	dir := t.TempDir()

	a := &reactQueryAgent{id: "passthrough-test"}
	dumper := a.newDebugPromptDumper(dir)

	msgs := testMessages()

	result := dumper(context.Background(), msgs)

	assert.Equal(t, len(msgs), len(result))
	for i := range msgs {
		assert.Same(t, msgs[i], result[i], "message %d should be the same pointer", i)
	}
}

func TestDebugPromptDumper_InvalidDir(t *testing.T) {
	a := &reactQueryAgent{id: "bad-dir-test"}
	dumper := a.newDebugPromptDumper("/nonexistent/path/that/does/not/exist")

	msgs := []*schema.Message{{Role: schema.User, Content: "hello"}}

	// Should not panic, should return messages unchanged
	result := dumper(context.Background(), msgs)
	assert.Equal(t, len(msgs), len(result))
	assert.Same(t, msgs[0], result[0])
}

func TestFormatMessagesMarkdown(t *testing.T) {
	msgs := testMessages()
	output := formatMessagesMarkdown("fmt-test-id", 42, msgs)

	assert.True(t, strings.HasPrefix(output, "# Agent Prompt - Step 42"))
	assert.Contains(t, output, "**Agent ID:** fmt-test-id")
	assert.Contains(t, output, "**Timestamp:**")

	// System message
	assert.Contains(t, output, "## Message 1 [system]")
	assert.Contains(t, output, "You are a helpful assistant.")

	// User message
	assert.Contains(t, output, "## Message 2 [user]")

	// Assistant with tool calls
	assert.Contains(t, output, "## Message 3 [assistant] (tool_calls)")
	assert.Contains(t, output, `**call_1**: search(`)

	// Tool response
	assert.Contains(t, output, "[tool: search] (call_id: call_1)")
}

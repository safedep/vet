package tui

import (
	"context"
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelToolCallMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, _ := m.Update(toolCallMsg{name: "my_tool", args: `{"key": "value"}`})
	model := updated.(*model)

	assert.Equal(t, 1, model.steps)
	require.Len(t, model.toolCalls, 1)
	assert.Equal(t, "my_tool", model.toolCalls[0].name)
	assert.Equal(t, `{"key": "value"}`, model.toolCalls[0].args)
}

func TestModelMultipleToolCalls(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	m.Update(toolCallMsg{name: "tool_a", args: `{}`})
	updated, _ := m.Update(toolCallMsg{name: "tool_b", args: `{"path": "main.py"}`})
	model := updated.(*model)

	assert.Equal(t, 2, model.steps)
	require.Len(t, model.toolCalls, 2)
}

func TestModelStatusMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, _ := m.Update(statusMsg("Analyzing patterns..."))
	model := updated.(*model)

	assert.Equal(t, "Analyzing patterns...", model.status)
}

func TestModelResultMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, cmd := m.Update(resultMsg("# Report\nAll clear."))
	model := updated.(*model)

	assert.Equal(t, "# Report\nAll clear.", model.rawResult)
	assert.Equal(t, "Rendering report...", model.status)
	assert.NotNil(t, cmd, "should return a render command")
}

func TestModelRenderedResultMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	// Simulate result followed by rendered result
	m.Update(resultMsg("# Report\nAll clear."))
	updated, _ := m.Update(renderedResultMsg("rendered content"))
	model := updated.(*model)

	assert.Equal(t, "rendered content", model.renderedResult)
	assert.False(t, model.done, "should not quit until execDone")
}

func TestModelRenderedResultAfterExecDone(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	// Result arrives, then exec completes, then render finishes
	m.Update(resultMsg("# Report"))
	m.Update(execDoneMsg{})
	updated, cmd := m.Update(renderedResultMsg("rendered"))
	model := updated.(*model)

	assert.True(t, model.done)
	assert.NotNil(t, cmd, "should return tea.Quit")
}

func TestModelErrorMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, cmd := m.Update(errorMsg{err: errors.New("API rate limit exceeded")})
	model := updated.(*model)

	assert.True(t, model.done)
	assert.EqualError(t, model.err, "API rate limit exceeded")
	assert.NotNil(t, cmd) // should be tea.Quit
}

func TestModelExecDoneMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	// No result pending, so execDone should quit immediately
	updated, cmd := m.Update(execDoneMsg{})
	model := updated.(*model)

	assert.True(t, model.execDone)
	assert.True(t, model.done)
	assert.Nil(t, model.err)
	assert.NotNil(t, cmd) // should be tea.Quit
}

func TestModelExecDoneWaitsForRender(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	// Result is pending but not yet rendered
	m.Update(resultMsg("# Report"))
	updated, cmd := m.Update(execDoneMsg{})
	model := updated.(*model)

	assert.True(t, model.execDone)
	assert.False(t, model.done, "should wait for render to complete")
	assert.Nil(t, cmd, "should not quit yet")
}

func TestModelCtrlC(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model := updated.(*model)

	assert.True(t, model.done)
	assert.NotNil(t, cmd) // should be tea.Quit
}

func TestModelWindowSize(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model := updated.(*model)

	assert.Equal(t, 120, model.width)
}

func TestModelWindowSizeReRendersResult(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	// Simulate a result already rendered
	m.rawResult = "# Report\nAll clear."
	m.renderedResult = "old rendered content"

	updated, cmd := m.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	model := updated.(*model)

	assert.Equal(t, 100, model.width)
	assert.NotNil(t, cmd, "should return a re-render command when result exists")
}

func TestModelWindowSizeNoReRenderWithoutResult(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, cmd := m.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	model := updated.(*model)

	assert.Equal(t, 100, model.width)
	assert.Nil(t, cmd, "should not return a command when no result exists")
}

func TestViewInProgress(t *testing.T) {
	m := newModel(context.Background(), nil, Config{
		Title:    "ClawHub Skill Scanner",
		Subtitle: "openai/gpt-4o",
	})

	// Add some tool calls
	m.Update(toolCallMsg{name: "clawhub_get_skill_info", args: `{"slug": "my-skill"}`})
	m.Update(toolCallMsg{name: "clawhub_list_skill_files", args: `{}`})

	view := m.View()

	assert.Contains(t, view, "ClawHub Skill Scanner")
	assert.Contains(t, view, "openai/gpt-4o")
	assert.Contains(t, view, "clawhub_get_skill_info")
	assert.Contains(t, view, `"slug": "my-skill"`)
	assert.Contains(t, view, "clawhub_list_skill_files")
	// Empty args ({}) should not show args line
	assert.NotContains(t, view, "└─ {}")
	assert.Contains(t, view, "2 steps")
}

func TestViewNoSubtitle(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test Agent"})

	view := m.View()

	assert.Contains(t, view, "Test Agent")
}

func TestViewDoneSuccess(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.done = true
	m.steps = 6
	m.rawResult = "# Report\nAll good."
	m.renderedResult = "Report\nAll good.\n"

	view := m.View()

	assert.Contains(t, view, "✓")
	assert.Contains(t, view, "Complete")
	assert.Contains(t, view, "6 steps")
	assert.Contains(t, view, "Report")
	assert.Contains(t, view, "All good")
}

func TestViewDoneError(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.done = true
	m.steps = 3
	m.err = errors.New("API rate limit exceeded")

	view := m.View()

	assert.Contains(t, view, "✗")
	assert.Contains(t, view, "Failed")
	assert.Contains(t, view, "3 steps")
	assert.Contains(t, view, "API rate limit exceeded")
}

func TestViewNoToolCalls(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.done = true
	m.rawResult = "Done"

	view := m.View()

	// Should not contain bullet points
	assert.NotContains(t, view, "●")
	assert.Contains(t, view, "✓")
}

func TestViewLongArgsTruncation(t *testing.T) {
	m := newModel(context.Background(), nil, Config{
		Title:            "Test",
		MaxToolArgLength: 20,
	})
	m.Update(toolCallMsg{name: "read_file", args: `{"path": "/very/long/path/to/some/deeply/nested/file.py"}`})

	view := m.View()

	// The full args should NOT appear
	assert.NotContains(t, view, "deeply/nested/file.py")
	// The truncated version should appear with ellipsis
	assert.Contains(t, view, "…")
}

func TestViewEmptyArgs(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.Update(toolCallMsg{name: "list_files", args: "{}"})

	view := m.View()

	assert.Contains(t, view, "list_files")
	// Should not show args connector for empty args
	assert.NotContains(t, view, "└─")
}

func TestViewBlankArgs(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.Update(toolCallMsg{name: "list_files", args: ""})

	view := m.View()

	assert.Contains(t, view, "list_files")
	assert.NotContains(t, view, "└─")
}

func TestConfigMaxArgLenDefault(t *testing.T) {
	c := Config{}
	assert.Equal(t, 80, c.maxArgLen())
}

func TestConfigMaxArgLenCustom(t *testing.T) {
	c := Config{MaxToolArgLength: 40}
	assert.Equal(t, 40, c.maxArgLen())
}

func TestConfigMaxArgLenZero(t *testing.T) {
	c := Config{MaxToolArgLength: 0}
	assert.Equal(t, 80, c.maxArgLen())
}

func TestEventSinkNilProgram(t *testing.T) {
	// Should not panic when program is nil
	sink := &eventSink{}
	assert.NotPanics(t, func() {
		sink.ToolCall("test", "{}")
		sink.Status("test")
		sink.Result("test")
		sink.Error(errors.New("test"))
		sink.Thinking("thinking about it")
	})
}

func TestModelThinkingMsg(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	updated, _ := m.Update(thinkingMsg("I need to analyze the file structure"))
	model := updated.(*model)

	assert.Equal(t, "I need to analyze the file structure", model.thinking)
}

func TestModelThinkingClearedOnToolCall(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	m.Update(thinkingMsg("Considering approach..."))
	updated, _ := m.Update(toolCallMsg{name: "read_file", args: `{"path": "main.py"}`})
	model := updated.(*model)

	assert.Equal(t, "", model.thinking)
}

func TestModelThinkingClearedOnResult(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	m.Update(thinkingMsg("Wrapping up analysis..."))
	updated, cmd := m.Update(resultMsg("# Report\nDone."))
	model := updated.(*model)

	assert.Equal(t, "", model.thinking)
	assert.NotNil(t, cmd, "should return a render command")
}

func TestViewThinking(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.Update(thinkingMsg("Analyzing the security implications of this dependency"))

	view := m.View()

	assert.Contains(t, view, "◈")
	assert.Contains(t, view, "Analyzing the security implications")
}

func TestViewThinkingTruncation(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.width = 30
	m.Update(thinkingMsg("This is a very long thinking content that should be truncated"))

	view := m.viewThinking()

	assert.Contains(t, view, "…")
}

func TestViewThinkingMultiline(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})
	m.Update(thinkingMsg("First line of thinking\nSecond line\nThird line"))

	view := m.viewThinking()

	assert.Contains(t, view, "First line of thinking")
	assert.NotContains(t, view, "Second line")
}

func TestViewThinkingEmpty(t *testing.T) {
	m := newModel(context.Background(), nil, Config{Title: "Test"})

	view := m.viewThinking()

	assert.Equal(t, "", view)
}

func TestFirstLine(t *testing.T) {
	assert.Equal(t, "hello", firstLine("hello\nworld"))
	assert.Equal(t, "single", firstLine("single"))
	assert.Equal(t, "", firstLine(""))
}

// Integration tests for Run() require a TTY, so they are skipped in CI
// and headless environments. To run them locally: go test -run TestRun -count=1

func TestRunSuccess(t *testing.T) {
	t.Skip("requires TTY; run manually with: go test -run TestRunSuccess -count=1")

	err := Run(context.Background(), func(ctx context.Context, sink EventSink) error {
		sink.Status("Starting...")
		time.Sleep(10 * time.Millisecond)
		sink.ToolCall("test_tool", `{"key": "value"}`)
		time.Sleep(10 * time.Millisecond)
		sink.Result("# Done\nAll good.")
		return nil
	}, Config{Title: "Integration Test"})

	assert.NoError(t, err)
}

func TestRunError(t *testing.T) {
	t.Skip("requires TTY; run manually with: go test -run TestRunError -count=1")

	err := Run(context.Background(), func(ctx context.Context, sink EventSink) error {
		sink.ToolCall("failing_tool", `{}`)
		return errors.New("something went wrong")
	}, Config{Title: "Error Test"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "something went wrong")
}

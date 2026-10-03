package prompt

import (
	"testing"

	"github.com/safedep/dry/tui/output"
	"github.com/stretchr/testify/assert"
)

func TestNoInputRefusesEveryPrompt(t *testing.T) {
	SetNoInput(true)
	t.Cleanup(func() { SetNoInput(false) })
	_, err := Confirm("ok?", true)
	assert.ErrorIs(t, err, ErrAgentMode)
	_, err = Prompt("name")
	assert.ErrorIs(t, err, ErrAgentMode)
	_, err = Select("pick", []string{"a"})
	assert.ErrorIs(t, err, ErrAgentMode)
	_, err = Secret("key")
	assert.ErrorIs(t, err, ErrAgentMode)
}

func TestAgentModeRefusesPrompts(t *testing.T) {
	prev := output.CurrentMode()
	output.SetMode(output.Agent)
	t.Cleanup(func() { output.SetMode(prev) })
	_, err := Confirm("ok?", true)
	assert.ErrorIs(t, err, ErrAgentMode)
}

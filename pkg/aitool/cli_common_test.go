package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLIVerifiers_VerifyOutput(t *testing.T) {
	t.Run("ClaudeCLI", func(t *testing.T) {
		v := &claudeCLIVerifier{}

		version, ok := v.VerifyOutput("Claude Code v1.2.3", "")
		assert.True(t, ok)
		assert.Equal(t, "1.2.3", version)

		version, ok = v.VerifyOutput("claude v0.9.1", "")
		assert.True(t, ok)
		assert.Equal(t, "0.9.1", version)

		version, ok = v.VerifyOutput("2.1.47 (Claude Code)", "")
		assert.True(t, ok)
		assert.Equal(t, "2.1.47", version)

		_, ok = v.VerifyOutput("some other tool", "")
		assert.False(t, ok)
	})

	t.Run("CursorCLI", func(t *testing.T) {
		v := &cursorCLIVerifier{}

		version, ok := v.VerifyOutput("2.4.37\n7b9c34466f5c119e93c3e654bb80fe9306b6cc70\narm64\n", "")
		assert.True(t, ok)
		assert.Equal(t, "2.4.37", version)

		version, ok = v.VerifyOutput("1.0.0\n", "")
		assert.True(t, ok)
		assert.Equal(t, "1.0.0", version)

		_, ok = v.VerifyOutput("not a version", "")
		assert.False(t, ok)
	})

	t.Run("Aider", func(t *testing.T) {
		v := &aiderVerifier{}

		version, ok := v.VerifyOutput("aider v0.82.1", "")
		assert.True(t, ok)
		assert.Equal(t, "0.82.1", version)

		version, ok = v.VerifyOutput("aider 0.82.1", "")
		assert.True(t, ok)
		assert.Equal(t, "0.82.1", version)

		_, ok = v.VerifyOutput("not aider", "")
		assert.False(t, ok)
	})

	t.Run("GhCopilot", func(t *testing.T) {
		v := &ghCopilotVerifier{}

		version, ok := v.VerifyOutput("gh copilot\tgithub/gh-copilot\tv1.0.5\n", "")
		assert.True(t, ok)
		assert.Equal(t, "1.0.5", version)

		_, ok = v.VerifyOutput("gh some-extension\tuser/some-ext\tv2.0.0\n", "")
		assert.False(t, ok)

		// Present but no version
		_, ok = v.VerifyOutput("github/gh-copilot\n", "")
		assert.True(t, ok)
	})

	t.Run("AmazonQ", func(t *testing.T) {
		v := &amazonQVerifier{}

		version, ok := v.VerifyOutput("Amazon Q Developer CLI 1.7.0", "")
		assert.True(t, ok)
		assert.Equal(t, "1.7.0", version)

		version, ok = v.VerifyOutput("", "aws q 2.0.0")
		assert.True(t, ok)
		assert.Equal(t, "2.0.0", version)

		// Not Amazon Q — just 'q' binary for something else
		_, ok = v.VerifyOutput("q version 1.0.0 - queue manager", "")
		assert.False(t, ok)
	})
}

func TestCLIToolDiscoverer_Interface(t *testing.T) {
	v := &aiderVerifier{}
	d := &cliToolDiscoverer{verifier: v}

	assert.Equal(t, "Aider CLI", d.Name())
	assert.Equal(t, "aider", d.Host())
}

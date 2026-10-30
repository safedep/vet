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

	t.Run("WindsurfCLI", func(t *testing.T) {
		v := &windsurfCLIVerifier{}

		version, ok := v.VerifyOutput("1.107.0\n16cc024632923bc387171d59cf5638057d4c8918\nx64\n", "")
		assert.True(t, ok)
		assert.Equal(t, "1.107.0", version)

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

	t.Run("CodexCLI", func(t *testing.T) {
		v := &codexCLIVerifier{}

		version, ok := v.VerifyOutput("codex-cli 0.160.1\n", "")
		assert.True(t, ok)
		assert.Equal(t, "0.160.1", version)

		// Warnings may precede the version line
		version, ok = v.VerifyOutput("codex-cli 0.160.1\n", "WARNING: proceeding, even though we could not create PATH aliases\n")
		assert.True(t, ok)
		assert.Equal(t, "0.160.1", version)

		_, ok = v.VerifyOutput("codex 1.0.0 - unrelated tool", "")
		assert.False(t, ok)
	})

	t.Run("GeminiCLI", func(t *testing.T) {
		v := &geminiCLIVerifier{}

		version, ok := v.VerifyOutput("0.62.0\n", "")
		assert.True(t, ok)
		assert.Equal(t, "0.62.0", version)

		_, ok = v.VerifyOutput("gemini: command help", "")
		assert.False(t, ok)
	})

	t.Run("CopilotCLI", func(t *testing.T) {
		v := &copilotCLIVerifier{}

		version, ok := v.VerifyOutput("GitHub Copilot CLI 1.0.92.\nRun 'copilot update' to check for updates.\n", "")
		assert.True(t, ok)
		assert.Equal(t, "1.0.92", version)

		_, ok = v.VerifyOutput("1.0.92\n", "")
		assert.False(t, ok)
	})

	t.Run("OpenCodeCLI", func(t *testing.T) {
		v := &openCodeCLIVerifier{}

		version, ok := v.VerifyOutput("1.18.34\n", "")
		assert.True(t, ok)
		assert.Equal(t, "1.18.34", version)

		_, ok = v.VerifyOutput("not a version", "")
		assert.False(t, ok)
	})

	t.Run("QwenCodeCLI", func(t *testing.T) {
		v := &qwenCodeCLIVerifier{}

		version, ok := v.VerifyOutput("0.25.0\n", "")
		assert.True(t, ok)
		assert.Equal(t, "0.25.0", version)

		_, ok = v.VerifyOutput("not a version", "")
		assert.False(t, ok)
	})

	t.Run("AmpCLI", func(t *testing.T) {
		v := &ampCLIVerifier{}

		version, ok := v.VerifyOutput("0.0.1791288059-gdc93b0 (released 2026-10-06T12:00:59.000Z, 1h ago)\n", "")
		assert.True(t, ok)
		assert.Equal(t, "0.0.1791288059", version)

		_, ok = v.VerifyOutput("amp 1.2.3\n", "")
		assert.False(t, ok)
	})

	t.Run("AugmentCLI", func(t *testing.T) {
		v := &augmentCLIVerifier{}

		version, ok := v.VerifyOutput("0.36.0 (commit 7c61e5bb)\n", "")
		assert.True(t, ok)
		assert.Equal(t, "0.36.0", version)

		_, ok = v.VerifyOutput("0.36.0\n", "")
		assert.False(t, ok)
	})
}

func TestCLIToolDiscoverer_Interface(t *testing.T) {
	v := &aiderVerifier{}
	d := &cliToolDiscoverer{verifier: v}

	assert.Equal(t, "Aider CLI", d.Name())
	assert.Equal(t, "aider", d.App())
}

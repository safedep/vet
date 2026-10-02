package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKnownAIExtensions_HasExpectedEntries(t *testing.T) {
	expectedIDs := []string{
		"github.copilot",
		"github.copilot-chat",
		"sourcegraph.cody-ai",
		"continue.continue",
		"tabnine.tabnine-vscode",
		"amazonwebservices.amazon-q-vscode",
		"saoudrizwan.claude-dev",
		"rooveterinaryinc.roo-cline",
		"codeium.codeium",
		"supermaven.supermaven",
	}

	for _, id := range expectedIDs {
		info, ok := knownAIExtensions[id]
		assert.True(t, ok, "expected known extension: %s", id)
		assert.NotEmpty(t, info.DisplayName, "display name should not be empty for: %s", id)
	}
}

func TestAIExtensionDiscoverer_Interface(t *testing.T) {
	d := &aiExtensionDiscoverer{}
	assert.Equal(t, "AI IDE Extensions", d.Name())
	assert.Equal(t, ideExtensionsApp, d.App())
}

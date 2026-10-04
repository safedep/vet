package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
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

func TestAIExtensionDiscoverer_EmitsKnownAIExtensionsOnly(t *testing.T) {
	r, err := newVSIXReaderFromDirs([]string{filepath.Join("fixtures", "ide_extension", ".vscode", "extensions")})
	require.NoError(t, err)
	d := &aiExtensionDiscoverer{reader: r}

	var items []*inventory.Item
	require.NoError(t, d.EnumTools(context.Background(), func(it *inventory.Item) error {
		items = append(items, it)
		return nil
	}))
	require.Len(t, items, 1)

	it := items[0]
	assert.Equal(t, inventory.KindAIExtension, it.Kind)
	assert.Equal(t, inventory.ScopeSystem, it.Scope)
	assert.Equal(t, "GitHub Copilot", it.Name)
	assert.Equal(t, ideExtensionsApp, it.App)
	assert.Equal(t, inventory.ItemIdentity(ideExtensionsApp, inventory.KindAIExtension, inventory.ScopeSystem,
		"github.copilot", it.ConfigPath), it.ItemIdentity, "the identity keys off the extension id")
	assert.Equal(t, "github.copilot", it.Metadata["extension.id"])
	assert.Equal(t, "VS Code", it.Metadata["app.display"])
	require.NotNil(t, it.IDEExtension)
	require.NotNil(t, it.IDEExtension.Package)
	assert.Equal(t, "github.copilot", it.IDEExtension.Package.Name)
	assert.Equal(t, "1.200.0", it.IDEExtension.Package.Version)
}

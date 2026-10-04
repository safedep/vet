package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
	"github.com/safedep/vet/v2/model"
)

func newFixtureDiscoverer(t testing.TB, config DiscoveryConfig) *ideExtensionDiscoverer {
	t.Helper()
	r, err := newVSIXReaderFromDirs([]string{filepath.Join("fixtures", "ide_extension", ".vscode", "extensions")})
	require.NoError(t, err)
	return &ideExtensionDiscoverer{config: config, reader: r}
}

func TestIDEExtensionDiscoverer_Interface(t *testing.T) {
	d := &ideExtensionDiscoverer{}
	assert.Equal(t, "IDE Extensions", d.Name())
	assert.Equal(t, ideExtensionApp, d.App())
}

func TestIDEExtensionDiscoverer_EmitsAllExtensions(t *testing.T) {
	d := newFixtureDiscoverer(t, DiscoveryConfig{})

	var tools []*inventory.Item
	err := d.EnumTools(context.Background(), func(tool *inventory.Item) error {
		tools = append(tools, tool)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, tools, 2, "all installed extensions must be emitted regardless of AI status")
}

func TestIDEExtensionDiscoverer_ToolType(t *testing.T) {
	d := newFixtureDiscoverer(t, DiscoveryConfig{})

	err := d.EnumTools(context.Background(), func(tool *inventory.Item) error {
		assert.Equal(t, inventory.KindIDEExtension, tool.Kind)
		assert.Equal(t, inventory.ScopeSystem, tool.Scope)
		return nil
	})

	require.NoError(t, err)
}

func TestIDEExtensionDiscoverer_ExtensionMetadata(t *testing.T) {
	d := newFixtureDiscoverer(t, DiscoveryConfig{})

	byID := map[string]*inventory.Item{}
	err := d.EnumTools(context.Background(), func(tool *inventory.Item) error {
		byID[tool.Metadata["extension.id"]] = tool
		return nil
	})
	require.NoError(t, err)

	t.Run("non-AI extension included", func(t *testing.T) {
		tool, ok := byID["ms-python.python"]
		require.True(t, ok)
		assert.Equal(t, "ms-python.python", tool.Name)
		assert.Equal(t, "2023.20.0", tool.Metadata["extension.version"])
		assert.Equal(t, "VS Code", tool.Metadata["extension.ide"])
		assert.Equal(t, "VS Code", tool.Metadata["app.display"])
		assert.Equal(t, &inventory.IDEExtensionDetail{
			Package: &inventory.PackageIdentity{
				Ecosystem: string(model.EcosystemVSCode),
				Name:      "ms-python.python",
				Version:   "2023.20.0",
			},
			IDE: "VS Code",
		}, tool.IDEExtension)
		assert.Equal(t, inventory.ItemIdentity(ideExtensionApp, inventory.KindIDEExtension, inventory.ScopeSystem,
			"ms-python.python", tool.ConfigPath), tool.ItemIdentity)
		assert.Equal(t, inventory.SourceID(ideExtensionApp, tool.ConfigPath), tool.SourceID)
	})

	t.Run("AI extension included", func(t *testing.T) {
		tool, ok := byID["github.copilot"]
		require.True(t, ok)
		assert.Equal(t, "github.copilot", tool.Name)
		assert.Equal(t, "1.200.0", tool.Metadata["extension.version"])
	})
}

func TestIDEExtensionDiscoverer_SystemScopeOnly(t *testing.T) {
	projectOnlyScope, err := NewDiscoveryScope(inventory.ScopeProject)
	require.NoError(t, err)

	d := newFixtureDiscoverer(t, DiscoveryConfig{Scope: projectOnlyScope})

	var count int
	err = d.EnumTools(context.Background(), func(*inventory.Item) error {
		count++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 0, count, "no extensions emitted when system scope is not enabled")
}

func TestIDEExtensionDiscoverer_StableIdentity(t *testing.T) {
	collectIDs := func() map[string]string {
		d := newFixtureDiscoverer(t, DiscoveryConfig{})
		ids := map[string]string{}
		require.NoError(t, d.EnumTools(context.Background(), func(tool *inventory.Item) error {
			ids[tool.Metadata["extension.id"]] = tool.ItemIdentity
			return nil
		}))
		return ids
	}

	assert.Equal(t, collectIDs(), collectIDs(), "item_identity must be deterministic across runs")
}

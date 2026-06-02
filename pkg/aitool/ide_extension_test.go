package aitool

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/readers"
)

func TestIDEExtensionDiscoverer_Interface(t *testing.T) {
	d := &ideExtensionDiscoverer{}
	assert.Equal(t, "IDE Extensions", d.Name())
	assert.Equal(t, ideExtensionApp, d.App())
}

func TestIDEExtensionDiscoverer_EmitsAllExtensions(t *testing.T) {
	fixturePath := filepath.Join("fixtures/ide_extension/.vscode/extensions")
	r, err := readers.NewVSIXExtReader([]string{fixturePath})
	require.NoError(t, err)

	d := &ideExtensionDiscoverer{
		config: DiscoveryConfig{},
		reader: r,
	}

	var tools []*AITool
	err = d.EnumTools(context.Background(), func(tool *AITool) error {
		tools = append(tools, tool)
		return nil
	})

	require.NoError(t, err)
	// Both AI and non-AI extensions must be reported
	require.Len(t, tools, 2, "all installed extensions must be emitted regardless of AI status")
}

func TestIDEExtensionDiscoverer_ToolType(t *testing.T) {
	fixturePath := filepath.Join("fixtures/ide_extension/.vscode/extensions")
	r, err := readers.NewVSIXExtReader([]string{fixturePath})
	require.NoError(t, err)

	d := &ideExtensionDiscoverer{config: DiscoveryConfig{}, reader: r}

	err = d.EnumTools(context.Background(), func(tool *AITool) error {
		assert.Equal(t, AIToolTypeIDEExtension, tool.Type)
		assert.Equal(t, AIToolScopeSystem, tool.Scope)
		return nil
	})

	require.NoError(t, err)
}

func TestIDEExtensionDiscoverer_ExtensionMetadata(t *testing.T) {
	fixturePath := filepath.Join("fixtures/ide_extension/.vscode/extensions")
	r, err := readers.NewVSIXExtReader([]string{fixturePath})
	require.NoError(t, err)

	d := &ideExtensionDiscoverer{config: DiscoveryConfig{}, reader: r}

	byID := map[string]*AITool{}
	err = d.EnumTools(context.Background(), func(tool *AITool) error {
		id, _ := tool.GetMeta("extension.id").(string)
		byID[id] = tool
		return nil
	})
	require.NoError(t, err)

	t.Run("non-AI extension included", func(t *testing.T) {
		tool, ok := byID["ms-python.python"]
		require.True(t, ok)
		assert.Equal(t, "ms-python.python", tool.Name)
		assert.Equal(t, "2023.20.0", tool.GetMeta("extension.version"))
		assert.Equal(t, "VS Code", tool.GetMeta("extension.ide"))
		assert.NotEmpty(t, tool.ID)
		assert.NotEmpty(t, tool.SourceID)
	})

	t.Run("AI extension included", func(t *testing.T) {
		tool, ok := byID["github.copilot"]
		require.True(t, ok)
		assert.Equal(t, "github.copilot", tool.Name)
		assert.Equal(t, "1.200.0", tool.GetMeta("extension.version"))
	})
}

func TestIDEExtensionDiscoverer_SystemScopeOnly(t *testing.T) {
	fixturePath := filepath.Join("fixtures/ide_extension/.vscode/extensions")
	r, err := readers.NewVSIXExtReader([]string{fixturePath})
	require.NoError(t, err)

	// Only project scope enabled — system scope (extensions) must be skipped.
	projectOnlyScope, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	d := &ideExtensionDiscoverer{
		config: DiscoveryConfig{Scope: projectOnlyScope},
		reader: r,
	}

	var count int
	err = d.EnumTools(context.Background(), func(*AITool) error {
		count++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 0, count, "no extensions emitted when system scope is not enabled")
}

func TestIDEExtensionDiscoverer_StableIdentity(t *testing.T) {
	fixturePath := filepath.Join("fixtures/ide_extension/.vscode/extensions")

	collectIDs := func() map[string]string {
		r, err := readers.NewVSIXExtReader([]string{fixturePath})
		require.NoError(t, err)
		d := &ideExtensionDiscoverer{config: DiscoveryConfig{}, reader: r}
		ids := map[string]string{}
		_ = d.EnumTools(context.Background(), func(tool *AITool) error {
			ids[tool.GetMeta("extension.id").(string)] = tool.ID
			return nil
		})
		return ids
	}

	assert.Equal(t, collectIDs(), collectIDs(), "item_identity must be deterministic across runs")
}

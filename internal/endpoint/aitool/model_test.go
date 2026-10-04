package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

func TestNewItem(t *testing.T) {
	tests := []struct {
		name       string
		appDisplay string
		wantMeta   map[string]string
	}{
		{"with app display", "Claude Code", map[string]string{metaKeyAppDisplay: "Claude Code"}},
		{"without app display", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			it := newItem(inventory.KindMCPServer, inventory.ScopeProject, "claude_code", tt.appDisplay, "safedep", "/p/.mcp.json")

			assert.Equal(t, inventory.KindMCPServer, it.Kind)
			assert.Equal(t, inventory.ScopeProject, it.Scope)
			assert.Equal(t, "claude_code", it.App)
			assert.Equal(t, "safedep", it.Name)
			assert.Equal(t, "/p/.mcp.json", it.ConfigPath)
			assert.Equal(t, inventory.ItemIdentity("claude_code", inventory.KindMCPServer, inventory.ScopeProject, "safedep", "/p/.mcp.json"), it.ItemIdentity)
			assert.Equal(t, inventory.SourceID("claude_code", "/p/.mcp.json"), it.SourceID)
			assert.Equal(t, tt.wantMeta, it.Metadata)
		})
	}
}

func TestNewItemSharesSourceIDPerConfigFile(t *testing.T) {
	a := newItem(inventory.KindMCPServer, inventory.ScopeSystem, "cursor", "Cursor", "a", "/h/.cursor/mcp.json")
	b := newItem(inventory.KindMCPServer, inventory.ScopeSystem, "cursor", "Cursor", "b", "/h/.cursor/mcp.json")

	assert.Equal(t, a.SourceID, b.SourceID)
	assert.NotEqual(t, a.ItemIdentity, b.ItemIdentity)
}

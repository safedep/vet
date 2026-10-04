package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

func TestNewDiscoveryScope_ValidScopes(t *testing.T) {
	ds, err := NewDiscoveryScope(inventory.ScopeSystem)
	require.NoError(t, err)
	assert.True(t, ds.IsEnabled(inventory.ScopeSystem))
	assert.False(t, ds.IsEnabled(inventory.ScopeProject))
}

func TestNewDiscoveryScope_MultipleScopes(t *testing.T) {
	ds, err := NewDiscoveryScope(inventory.ScopeSystem, inventory.ScopeProject)
	require.NoError(t, err)
	assert.True(t, ds.IsEnabled(inventory.ScopeSystem))
	assert.True(t, ds.IsEnabled(inventory.ScopeProject))
}

func TestNewDiscoveryScope_UnknownScope(t *testing.T) {
	_, err := NewDiscoveryScope(inventory.Scope(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scope")
}

func TestNewDiscoveryScope_Empty(t *testing.T) {
	ds, err := NewDiscoveryScope()
	require.NoError(t, err)
	assert.True(t, ds.IsEnabled(inventory.ScopeSystem))
	assert.True(t, ds.IsEnabled(inventory.ScopeProject))
	assert.True(t, ds.All())
}

func TestAllScopes(t *testing.T) {
	ds := AllScopes()
	assert.True(t, ds.All())
	assert.True(t, ds.IsEnabled(inventory.ScopeSystem))
	assert.True(t, ds.IsEnabled(inventory.ScopeProject))
}

func TestDiscoveryScope_All(t *testing.T) {
	ds, err := NewDiscoveryScope(inventory.ScopeSystem)
	require.NoError(t, err)
	assert.False(t, ds.All())

	ds2, err := NewDiscoveryScope()
	require.NoError(t, err)
	assert.True(t, ds2.All())
}

func TestDiscoveryScope_Validate(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []inventory.Scope
		config  DiscoveryConfig
		wantErr string
	}{
		{
			name:   "system scope with home dir",
			scopes: []inventory.Scope{inventory.ScopeSystem},
			config: DiscoveryConfig{HomeDir: "/home/user"},
		},
		{
			name:    "system scope without home dir",
			scopes:  []inventory.Scope{inventory.ScopeSystem},
			config:  DiscoveryConfig{},
			wantErr: "requires HomeDir",
		},
		{
			name:   "project scope with project dir",
			scopes: []inventory.Scope{inventory.ScopeProject},
			config: DiscoveryConfig{ProjectDir: "/my/project"},
		},
		{
			name:    "project scope without project dir",
			scopes:  []inventory.Scope{inventory.ScopeProject},
			config:  DiscoveryConfig{},
			wantErr: "requires ProjectDir",
		},
		{
			name:   "both scopes satisfied",
			scopes: []inventory.Scope{inventory.ScopeSystem, inventory.ScopeProject},
			config: DiscoveryConfig{HomeDir: "/home/user", ProjectDir: "/my/project"},
		},
		{
			name:    "all scopes (empty) needs both dirs",
			scopes:  nil,
			config:  DiscoveryConfig{HomeDir: "/home/user"},
			wantErr: "requires ProjectDir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ds *DiscoveryScope
			var err error
			if tt.scopes == nil {
				ds = AllScopes()
			} else {
				ds, err = NewDiscoveryScope(tt.scopes...)
				require.NoError(t, err)
			}

			err = ds.Validate(tt.config)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDiscoveryConfig_ScopeEnabled_NilScope(t *testing.T) {
	config := DiscoveryConfig{}
	assert.True(t, config.ScopeEnabled(inventory.ScopeSystem))
	assert.True(t, config.ScopeEnabled(inventory.ScopeProject))
}

func TestDiscoveryConfig_ScopeEnabled_WithScope(t *testing.T) {
	ds, err := NewDiscoveryScope(inventory.ScopeProject)
	require.NoError(t, err)

	config := DiscoveryConfig{Scope: ds}
	assert.False(t, config.ScopeEnabled(inventory.ScopeSystem))
	assert.True(t, config.ScopeEnabled(inventory.ScopeProject))
}

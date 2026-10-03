package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiscoveryScope_ValidScopes(t *testing.T) {
	ds, err := NewDiscoveryScope(AIToolScopeSystem)
	require.NoError(t, err)
	assert.True(t, ds.IsEnabled(AIToolScopeSystem))
	assert.False(t, ds.IsEnabled(AIToolScopeProject))
}

func TestNewDiscoveryScope_MultipleScopes(t *testing.T) {
	ds, err := NewDiscoveryScope(AIToolScopeSystem, AIToolScopeProject)
	require.NoError(t, err)
	assert.True(t, ds.IsEnabled(AIToolScopeSystem))
	assert.True(t, ds.IsEnabled(AIToolScopeProject))
}

func TestNewDiscoveryScope_UnknownScope(t *testing.T) {
	_, err := NewDiscoveryScope(AIToolScope("bogus"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scope")
}

func TestNewDiscoveryScope_Empty(t *testing.T) {
	ds, err := NewDiscoveryScope()
	require.NoError(t, err)
	assert.True(t, ds.IsEnabled(AIToolScopeSystem))
	assert.True(t, ds.IsEnabled(AIToolScopeProject))
	assert.True(t, ds.All())
}

func TestAllScopes(t *testing.T) {
	ds := AllScopes()
	assert.True(t, ds.All())
	assert.True(t, ds.IsEnabled(AIToolScopeSystem))
	assert.True(t, ds.IsEnabled(AIToolScopeProject))
}

func TestDiscoveryScope_All(t *testing.T) {
	ds, err := NewDiscoveryScope(AIToolScopeSystem)
	require.NoError(t, err)
	assert.False(t, ds.All())

	ds2, err := NewDiscoveryScope()
	require.NoError(t, err)
	assert.True(t, ds2.All())
}

func TestDiscoveryScope_Validate(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []AIToolScope
		config  DiscoveryConfig
		wantErr string
	}{
		{
			name:   "system scope with home dir",
			scopes: []AIToolScope{AIToolScopeSystem},
			config: DiscoveryConfig{HomeDir: "/home/user"},
		},
		{
			name:    "system scope without home dir",
			scopes:  []AIToolScope{AIToolScopeSystem},
			config:  DiscoveryConfig{},
			wantErr: "requires HomeDir",
		},
		{
			name:   "project scope with project dir",
			scopes: []AIToolScope{AIToolScopeProject},
			config: DiscoveryConfig{ProjectDir: "/my/project"},
		},
		{
			name:    "project scope without project dir",
			scopes:  []AIToolScope{AIToolScopeProject},
			config:  DiscoveryConfig{},
			wantErr: "requires ProjectDir",
		},
		{
			name:   "both scopes satisfied",
			scopes: []AIToolScope{AIToolScopeSystem, AIToolScopeProject},
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
	assert.True(t, config.ScopeEnabled(AIToolScopeSystem))
	assert.True(t, config.ScopeEnabled(AIToolScopeProject))
}

func TestDiscoveryConfig_ScopeEnabled_WithScope(t *testing.T) {
	ds, err := NewDiscoveryScope(AIToolScopeProject)
	require.NoError(t, err)

	config := DiscoveryConfig{Scope: ds}
	assert.False(t, config.ScopeEnabled(AIToolScopeSystem))
	assert.True(t, config.ScopeEnabled(AIToolScopeProject))
}

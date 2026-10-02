package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanConfigScopeEnabledNilScopesEnablesAll(t *testing.T) {
	cfg := ScanConfig{}
	assert.True(t, cfg.ScopeEnabled(ScopeSystem))
	assert.True(t, cfg.ScopeEnabled(ScopeProject))
	assert.True(t, cfg.ScopeEnabled(ScopeUnspecified))
}

func TestScanConfigScopeEnabledRespectsAllowList(t *testing.T) {
	cfg := ScanConfig{Scopes: []Scope{ScopeSystem}}
	assert.True(t, cfg.ScopeEnabled(ScopeSystem))
	assert.False(t, cfg.ScopeEnabled(ScopeProject))
}

func TestScanConfigScopeEnabledEmptySliceDisablesAll(t *testing.T) {
	// An explicitly empty slice is distinct from nil: it allows nothing.
	cfg := ScanConfig{Scopes: []Scope{}}
	assert.False(t, cfg.ScopeEnabled(ScopeSystem))
	assert.False(t, cfg.ScopeEnabled(ScopeProject))
}

func TestScanConfigScopeEnabledMultipleScopes(t *testing.T) {
	cfg := ScanConfig{Scopes: []Scope{ScopeSystem, ScopeProject}}
	assert.True(t, cfg.ScopeEnabled(ScopeSystem))
	assert.True(t, cfg.ScopeEnabled(ScopeProject))
	assert.False(t, cfg.ScopeEnabled(ScopeUnspecified))
}

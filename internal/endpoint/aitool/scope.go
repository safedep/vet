package aitool

import "fmt"

// ScopeMetadata describes the prerequisites for a scope.
type ScopeMetadata struct {
	RequiresHomeDir    bool
	RequiresProjectDir bool
}

// knownScopes maps each scope to its metadata.
var knownScopes = map[AIToolScope]ScopeMetadata{
	AIToolScopeSystem: {
		RequiresHomeDir: true,
	},
	AIToolScopeProject: {
		RequiresProjectDir: true,
	},
}

// DiscoveryScope controls which scopes are active during discovery.
// An empty set means all scopes are enabled.
type DiscoveryScope struct {
	enabled map[AIToolScope]bool
}

// NewDiscoveryScope creates a scope filter from the given scope names.
// Returns an error if any scope name is not recognized.
func NewDiscoveryScope(scopes ...AIToolScope) (*DiscoveryScope, error) {
	ds := &DiscoveryScope{enabled: make(map[AIToolScope]bool)}
	for _, s := range scopes {
		if _, ok := knownScopes[s]; !ok {
			return nil, fmt.Errorf("unknown scope: %q", s)
		}
		ds.enabled[s] = true
	}
	return ds, nil
}

// AllScopes returns a scope with nothing filtered.
func AllScopes() *DiscoveryScope {
	return &DiscoveryScope{enabled: make(map[AIToolScope]bool)}
}

// IsEnabled reports whether the given scope should be scanned.
// Returns true when no scopes are explicitly selected (all enabled).
func (ds *DiscoveryScope) IsEnabled(scope AIToolScope) bool {
	if len(ds.enabled) == 0 {
		return true
	}
	return ds.enabled[scope]
}

// All reports whether all scopes are enabled (no filtering).
func (ds *DiscoveryScope) All() bool {
	return len(ds.enabled) == 0
}

// Validate checks that the DiscoveryConfig satisfies the prerequisites
// of all enabled scopes.
func (ds *DiscoveryScope) Validate(config DiscoveryConfig) error {
	scopes := make([]AIToolScope, 0, len(ds.enabled))
	if len(ds.enabled) == 0 {
		for s := range knownScopes {
			scopes = append(scopes, s)
		}
	} else {
		for s := range ds.enabled {
			scopes = append(scopes, s)
		}
	}
	for _, scope := range scopes {
		meta := knownScopes[scope]
		if meta.RequiresHomeDir && config.HomeDir == "" {
			return fmt.Errorf("scope %q requires HomeDir to be set", scope)
		}
		if meta.RequiresProjectDir && config.ProjectDir == "" {
			return fmt.Errorf("scope %q requires ProjectDir to be set", scope)
		}
	}
	return nil
}

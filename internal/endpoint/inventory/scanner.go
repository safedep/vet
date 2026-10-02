package inventory

import "context"

// ScanConfig carries the inputs every scanner needs to run a discovery pass.
// It is read-only; orchestrators copy it by value into each scanner.
type ScanConfig struct {
	// HomeDir overrides the user home directory; empty string means
	// "use the OS-detected home".
	HomeDir string
	// ProjectDir is the project root for project-scoped discovery; empty
	// string means project-scoped discovery is skipped.
	ProjectDir string
	// Scopes is the allowlist of scopes a scanner should enumerate.
	// A nil slice means "all scopes enabled" (mirrors aitool.DiscoveryConfig
	// semantics). An empty (non-nil) slice means "no scopes enabled".
	Scopes []Scope
}

// ScopeEnabled reports whether the given scope is permitted by this config.
// When Scopes is nil, every scope is enabled.
func (c ScanConfig) ScopeEnabled(scope Scope) bool {
	if c.Scopes == nil {
		return true
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// EmitFunc is the per-item callback supplied to Scanner.Scan. Returning a
// non-nil error tells the scanner to stop enumeration and return that error
// to the orchestrator.
type EmitFunc func(*Item) error

// Scanner enumerates items of one or more inventory kinds from the local
// endpoint. Implementations are stateless with respect to the orchestrator;
// any caching is the implementation's concern.
type Scanner interface {
	// Name is a stable, log-safe identifier (e.g. "aitool", "browser_ext").
	Name() string
	// Scan walks the configured sources and invokes emit for each item.
	// Scan returns nil on success, the emit-callback's error if it
	// requested early termination, or a discoverer-level failure.
	Scan(ctx context.Context, cfg ScanConfig, emit EmitFunc) error
}

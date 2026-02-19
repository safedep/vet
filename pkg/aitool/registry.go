package aitool

import (
	"github.com/safedep/vet/pkg/common/logger"
)

// DiscoveryConfig provides context for AI tool discovery.
type DiscoveryConfig struct {
	// HomeDir overrides the user home directory (for testing)
	HomeDir string

	// ProjectDir is the project root for project-level discovery.
	// Empty string means skip project-level discovery.
	ProjectDir string
}

// AIToolDiscovererFactory creates a reader given a config.
type AIToolDiscovererFactory func(config DiscoveryConfig) (AIToolReader, error)

type registryEntry struct {
	name    string
	factory AIToolDiscovererFactory
}

// Registry holds discoverer factories in registration order.
type Registry struct {
	entries []registryEntry
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a discoverer factory to the registry.
func (r *Registry) Register(name string, factory AIToolDiscovererFactory) {
	r.entries = append(r.entries, registryEntry{name: name, factory: factory})
}

// Discover runs all registered discoverers and calls handler for each tool found.
// Factory or discoverer errors are logged and skipped; handler errors propagate immediately.
func (r *Registry) Discover(config DiscoveryConfig, handler AIToolHandlerFn) error {
	for _, entry := range r.entries {
		reader, err := entry.factory(config)
		if err != nil {
			logger.Warnf("Failed to create discoverer %s: %v", entry.name, err)
			continue
		}

		err = reader.EnumTools(handler)
		if err != nil {
			return err
		}
	}

	return nil
}

// DefaultRegistry returns a registry wired with all built-in discoverers.
func DefaultRegistry() *Registry {
	r := NewRegistry()

	// Config-based discoverers
	r.Register("claude_code_config", NewClaudeCodeDiscoverer)
	r.Register("cursor_config", NewCursorDiscoverer)

	// CLI tool discoverers
	r.Register("claude_code_cli", NewClaudeCLIDiscoverer)
	r.Register("cursor_cli", NewCursorCLIDiscoverer)
	r.Register("aider", NewAiderDiscoverer)
	r.Register("gh_copilot", NewGhCopilotDiscoverer)
	r.Register("amazon_q", NewAmazonQDiscoverer)

	// IDE extension discoverer
	r.Register("ide_extensions", NewAIExtensionDiscoverer)

	return r
}

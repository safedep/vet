package aitool

import (
	"context"

	"github.com/safedep/vet/pkg/common/logger"
)

// DiscoveryConfig provides context for AI tool discovery.
type DiscoveryConfig struct {
	// HomeDir overrides the user home directory (for testing)
	HomeDir string

	// ProjectDir is the project root for project-level discovery.
	// Empty string means skip project-level discovery.
	ProjectDir string

	// Scope controls which scopes are active during discovery.
	// Nil means all scopes are enabled.
	Scope *DiscoveryScope
}

// ScopeEnabled is a convenience method that checks whether the given scope
// is active in this config. Returns true when Scope is nil (all enabled).
func (c DiscoveryConfig) ScopeEnabled(scope AIToolScope) bool {
	if c.Scope == nil {
		return true
	}
	return c.Scope.IsEnabled(scope)
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
// Coding agents are held back until every discoverer has run, because their
// install evidence (agent.installed, agent.evidence) depends on CLI and
// extension items that later discoverers emit.
func (r *Registry) Discover(ctx context.Context, config DiscoveryConfig, handler AIToolHandlerFn) error {
	evidence := newInstallEvidence()
	var agents []*AITool

	collect := func(tool *AITool) error {
		if tool == nil {
			return handler(tool)
		}
		if tool.Type == AIToolTypeCodingAgent {
			agents = append(agents, tool)
			return nil
		}
		evidence.observe(tool)
		return handler(tool)
	}

	for _, entry := range r.entries {
		reader, err := entry.factory(config)
		if err != nil {
			logger.Warnf("Failed to create discoverer %s: %v", entry.name, err)
			continue
		}

		err = reader.EnumTools(ctx, collect)
		if err != nil {
			return err
		}
	}

	for _, agent := range agents {
		evidence.enrich(agent)
		if err := handler(agent); err != nil {
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
	r.Register("claude_code_user_config", NewClaudeCodeUserConfigDiscoverer)
	r.Register("cursor_config", NewCursorDiscoverer)
	r.Register("windsurf_config", NewWindsurfDiscoverer)
	r.Register("antigravity_config", NewAntigravityDiscoverer)
	r.Register("vscode_config", NewVSCodeDiscoverer)
	r.Register("codex_config", NewCodexDiscoverer)
	r.Register("gemini_cli_config", NewGeminiDiscoverer)
	r.Register("copilot_cli_config", NewCopilotDiscoverer)
	r.Register("opencode_config", NewOpenCodeDiscoverer)
	r.Register("qwen_code_config", NewQwenCodeDiscoverer)
	r.Register("amp_config", NewAmpDiscoverer)
	r.Register("augment_config", NewAugmentDiscoverer)
	r.Register("kiro_config", NewKiroDiscoverer)
	r.Register("amazon_q_config", NewAmazonQConfigDiscoverer)
	r.Register("junie_config", NewJunieDiscoverer)
	r.Register("goose_config", NewGooseDiscoverer)
	r.Register("continue_config", NewContinueDiscoverer)
	r.Register("zed_config", NewZedDiscoverer)
	r.Register("cline_config", NewClineDiscoverer)
	r.Register("roo_code_config", NewRooCodeDiscoverer)

	// CLI tool discoverers
	r.Register("claude_code_cli", NewClaudeCLIDiscoverer)
	r.Register("cursor_cli", NewCursorCLIDiscoverer)
	r.Register("windsurf_cli", NewWindsurfCLIDiscoverer)
	r.Register("antigravity_cli", NewAntigravityCLIDiscoverer)
	r.Register("vscode_cli", NewVSCodeCLIDiscoverer)
	r.Register("aider", NewAiderDiscoverer)
	r.Register("gh_copilot", NewGhCopilotDiscoverer)
	r.Register("amazon_q", NewAmazonQDiscoverer)
	r.Register("codex_cli", NewCodexCLIDiscoverer)
	r.Register("gemini_cli", NewGeminiCLIDiscoverer)
	r.Register("copilot_cli", NewCopilotCLIDiscoverer)
	r.Register("opencode_cli", NewOpenCodeCLIDiscoverer)
	r.Register("qwen_code_cli", NewQwenCodeCLIDiscoverer)
	r.Register("amp_cli", NewAmpCLIDiscoverer)
	r.Register("augment_cli", NewAugmentCLIDiscoverer)

	// IDE extension discoverer
	r.Register("ide_extensions", NewAIExtensionDiscoverer)

	return r
}

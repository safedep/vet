package aitool

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
)

type claudeCodeUserConfigDiscoverer struct {
	homeDir string
	config  DiscoveryConfig
}

// NewClaudeCodeUserConfigDiscoverer creates a discoverer for Claude Code's
// user-level MCP config (~/.claude.json) and plugin-installed MCPs
// (~/.claude/plugins/cache/**/.mcp.json). These are distinct from app-level
// settings (~/.claude/settings.json) handled by NewClaudeCodeDiscoverer.
func NewClaudeCodeUserConfigDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &claudeCodeUserConfigDiscoverer{homeDir: homeDir, config: config}, nil
}

func (d *claudeCodeUserConfigDiscoverer) Name() string { return "Claude Code User Config" }
func (d *claudeCodeUserConfigDiscoverer) App() string  { return claudeCodeApp }

func (d *claudeCodeUserConfigDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}
	if err := d.processUserConfig(handler); err != nil {
		return err
	}
	return d.walkPluginCache(handler)
}

// processUserConfig reads ~/.claude.json, which is Claude Code's user-level
// MCP registry. It uses the same mcpServers JSON format as settings.json.
func (d *claudeCodeUserConfigDiscoverer) processUserConfig(handler AIToolHandlerFn) error {
	path := filepath.Join(d.homeDir, ".claude.json")
	cfg, err := parseMCPAppConfig(path)
	if err != nil {
		logger.Debugf("Claude Code user config not found or unreadable: %s", path)
		return nil
	}
	return emitMCPServers(cfg, path, AIToolScopeSystem, claudeCodeApp, claudeCodeAppDisplay, handler)
}

// walkPluginCache walks ~/.claude/plugins/cache/**/.mcp.json and emits MCPs
// from each file found. Plugin publishers use two formats: the standard
// mcpServers-wrapped object, and a bare map of server-name to entry. Both
// are handled via parsePluginMCPConfig.
func (d *claudeCodeUserConfigDiscoverer) walkPluginCache(handler AIToolHandlerFn) error {
	cacheDir := filepath.Join(d.homeDir, ".claude", "plugins", "cache")
	return filepath.WalkDir(cacheDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths silently
		}
		if entry.IsDir() || entry.Name() != ".mcp.json" {
			return nil
		}
		cfg, parseErr := parsePluginMCPConfig(path)
		if parseErr != nil {
			logger.Debugf("Claude Code plugin MCP config unreadable: %s: %v", path, parseErr)
			return nil
		}
		return emitMCPServers(cfg, path, AIToolScopeSystem, claudeCodeApp, claudeCodeAppDisplay, handler)
	})
}

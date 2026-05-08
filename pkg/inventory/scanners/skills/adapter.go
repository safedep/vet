package skills

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/inventory"
)

const (
	scannerName = "skills"

	// appGlobalSkills is the App name used for skill directories that are
	// shared by multiple agents (e.g. .agents/skills/). Using a single name
	// avoids emitting the same skill once per agent that claims the path.
	appGlobalSkills = "Global Skills"
)

// pathEntry is a (relative path, app name) pair for one scope.
// Path is relative to cfg.ProjectDir (project scope) or homeDir (system scope).
type pathEntry struct {
	App  string
	Path string
}

// projectPaths lists the unique project-scoped skill directories to scan.
// Paths shared by multiple agents are collapsed into a single appGlobalSkills entry.
var projectPaths = []pathEntry{
	// .agents/skills/ is the shared convention used by amp, kimi-cli, replit,
	// universal, antigravity, cline, warp, codex, cursor, deepagents,
	// firebender, gemini-cli, github-copilot, and opencode.
	{App: appGlobalSkills, Path: ".agents/skills"},
	// Agent-specific project paths below.
	{App: "augment", Path: ".augment/skills"},
	{App: "bob", Path: ".bob/skills"},
	{App: "claude-code", Path: ".claude/skills"},
	{App: "codebuddy", Path: ".codebuddy/skills"},
	{App: "command-code", Path: ".commandcode/skills"},
	{App: "continue", Path: ".continue/skills"},
	{App: "cortex", Path: ".cortex/skills"},
	{App: "crush", Path: ".crush/skills"},
	{App: "droid", Path: ".factory/skills"},
	{App: "goose", Path: ".goose/skills"},
	{App: "iflow-cli", Path: ".iflow/skills"},
	{App: "junie", Path: ".junie/skills"},
	{App: "kilo", Path: ".kilocode/skills"},
	{App: "kiro-cli", Path: ".kiro/skills"},
	{App: "kode", Path: ".kode/skills"},
	{App: "mcpjam", Path: ".mcpjam/skills"},
	{App: "mistral-vibe", Path: ".vibe/skills"},
	{App: "mux", Path: ".mux/skills"},
	{App: "openclaw", Path: "skills"},
	{App: "openhands", Path: ".openhands/skills"},
	{App: "pi", Path: ".pi/skills"},
	{App: "qoder", Path: ".qoder/skills"},
	{App: "qwen-code", Path: ".qwen/skills"},
	{App: "roo", Path: ".roo/skills"},
	// trae and trae-cn share .trae/skills/ at project scope.
	{App: "trae", Path: ".trae/skills"},
	{App: "windsurf", Path: ".windsurf/skills"},
	{App: "zencoder", Path: ".zencoder/skills"},
	{App: "neovate", Path: ".neovate/skills"},
	{App: "pochi", Path: ".pochi/skills"},
	{App: "adal", Path: ".adal/skills"},
}

// globalPaths lists the unique system-scoped (home-relative) skill directories
// to scan. Paths shared by multiple agents are collapsed into appGlobalSkills.
var globalPaths = []pathEntry{
	// ~/.config/agents/skills/ is shared by amp, kimi-cli, replit, universal.
	{App: appGlobalSkills, Path: ".config/agents/skills"},
	// ~/.agents/skills/ is shared by cline and warp.
	{App: appGlobalSkills, Path: ".agents/skills"},
	// Agent-specific global paths below.
	{App: "antigravity", Path: ".gemini/antigravity/skills"},
	{App: "augment", Path: ".augment/skills"},
	{App: "bob", Path: ".bob/skills"},
	{App: "claude-code", Path: ".claude/skills"},
	{App: "codebuddy", Path: ".codebuddy/skills"},
	{App: "codex", Path: ".codex/skills"},
	{App: "command-code", Path: ".commandcode/skills"},
	{App: "continue", Path: ".continue/skills"},
	{App: "cortex", Path: ".snowflake/cortex/skills"},
	{App: "crush", Path: ".config/crush/skills"},
	{App: "cursor", Path: ".cursor/skills"},
	{App: "deepagents", Path: ".deepagents/agent/skills"},
	{App: "droid", Path: ".factory/skills"},
	{App: "firebender", Path: ".firebender/skills"},
	{App: "gemini-cli", Path: ".gemini/skills"},
	{App: "github-copilot", Path: ".copilot/skills"},
	{App: "goose", Path: ".config/goose/skills"},
	{App: "iflow-cli", Path: ".iflow/skills"},
	{App: "junie", Path: ".junie/skills"},
	{App: "kilo", Path: ".kilocode/skills"},
	{App: "kiro-cli", Path: ".kiro/skills"},
	{App: "kode", Path: ".kode/skills"},
	{App: "mcpjam", Path: ".mcpjam/skills"},
	{App: "mistral-vibe", Path: ".vibe/skills"},
	{App: "mux", Path: ".mux/skills"},
	{App: "openclaw", Path: ".openclaw/skills"},
	{App: "opencode", Path: ".config/opencode/skills"},
	{App: "openhands", Path: ".openhands/skills"},
	{App: "pi", Path: ".pi/agent/skills"},
	{App: "qoder", Path: ".qoder/skills"},
	{App: "qwen-code", Path: ".qwen/skills"},
	{App: "roo", Path: ".roo/skills"},
	{App: "trae", Path: ".trae/skills"},
	{App: "trae-cn", Path: ".trae-cn/skills"},
	{App: "windsurf", Path: ".codeium/windsurf/skills"},
	{App: "zencoder", Path: ".zencoder/skills"},
	{App: "neovate", Path: ".neovate/skills"},
	{App: "pochi", Path: ".pochi/skills"},
	{App: "adal", Path: ".adal/skills"},
}

type adapter struct{}

// New constructs an inventory.Scanner that discovers agent skill directories
// for all supported agents.
func New() inventory.Scanner {
	return &adapter{}
}

// Name returns the stable scanner identifier used in logs and ScanError.
func (a *adapter) Name() string { return scannerName }

// Scan walks each entry in projectPaths (when project scope is enabled) and
// globalPaths (when system scope is enabled), emitting one Item per skill
// subdirectory found.
func (a *adapter) Scan(ctx context.Context, cfg inventory.ScanConfig, emit inventory.EmitFunc) error {
	if cfg.ScopeEnabled(inventory.ScopeProject) && cfg.ProjectDir != "" {
		for _, e := range projectPaths {
			dir := filepath.Join(cfg.ProjectDir, e.Path)
			if err := scanDir(ctx, dir, e.App, "", inventory.ScopeProject, emit); err != nil {
				return err
			}
		}
	}

	if cfg.ScopeEnabled(inventory.ScopeSystem) {
		homeDir := cfg.HomeDir
		if homeDir == "" {
			if h, err := os.UserHomeDir(); err == nil {
				homeDir = h
			}
		}
		if homeDir != "" {
			for _, e := range globalPaths {
				dir := filepath.Join(homeDir, e.Path)
				if err := scanDir(ctx, dir, e.App, "", inventory.ScopeSystem, emit); err != nil {
					return err
				}
			}
			if err := scanClaudePluginSkills(ctx, homeDir, inventory.ScopeSystem, emit); err != nil {
				return err
			}
			if err := scanClaudeMarketplaceSkills(ctx, homeDir, inventory.ScopeSystem, emit); err != nil {
				return err
			}
		}
	}

	return nil
}

// scanClaudePluginSkills globs ~/.claude/plugins/cache/<org>/<plugin>/<version>/skills/
// App is "claude-code"; Name is "<plugin>/<skill-name>".
func scanClaudePluginSkills(ctx context.Context, homeDir string, scope inventory.Scope, emit inventory.EmitFunc) error {
	pattern := filepath.Join(homeDir, ".claude", "plugins", "cache", "*", "*", "*", "skills")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	for _, skillsDir := range matches {
		// Extract plugin name: cache/<org>/<plugin>/<version>/skills → plugin is [len-3]
		parts := strings.Split(filepath.ToSlash(skillsDir), "/")
		if len(parts) < 3 {
			continue
		}
		pluginName := parts[len(parts)-3]
		if err := scanDir(ctx, skillsDir, "claude-code", pluginName+"/", scope, emit); err != nil {
			return err
		}
	}
	return nil
}

// scanClaudeMarketplaceSkills globs
// ~/.claude/plugins/marketplaces/<marketplace>/plugins/<plugin>/skills/
// App is "claude-code"; Name is "<plugin>/<skill-name>".
func scanClaudeMarketplaceSkills(ctx context.Context, homeDir string, scope inventory.Scope, emit inventory.EmitFunc) error {
	pattern := filepath.Join(homeDir, ".claude", "plugins", "marketplaces", "*", "plugins", "*", "skills")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	for _, skillsDir := range matches {
		// Extract plugin name: .../plugins/<plugin>/skills → plugin is [len-2]
		parts := strings.Split(filepath.ToSlash(skillsDir), "/")
		if len(parts) < 2 {
			continue
		}
		pluginName := parts[len(parts)-2]
		if err := scanDir(ctx, skillsDir, "claude-code", pluginName+"/", scope, emit); err != nil {
			return err
		}
	}
	return nil
}

// scanDir lists subdirectories of dir and emits one Item per directory found.
// namePrefix is prepended to the skill name (e.g. "superpowers/" for plugin skills).
// Missing or unreadable directories are silently skipped.
func scanDir(_ context.Context, dir, app, namePrefix string, scope inventory.Scope, emit inventory.EmitFunc) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		s := &skill{
			App:        app,
			Name:       namePrefix + e.Name(),
			Scope:      scope,
			ConfigPath: filepath.Join(dir, e.Name()),
			SkillsDir:  dir,
		}
		if err := emit(translate(s)); err != nil {
			return err
		}
	}
	return nil
}

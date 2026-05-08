package skills

import (
	"context"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/inventory"
)

const scannerName = "skills"

// agentEntry maps an agent identifier to its project-local and global skill
// directory paths. ProjectPath is relative to cfg.ProjectDir; GlobalPath is
// relative to cfg.HomeDir.
type agentEntry struct {
	App         string
	ProjectPath string
	GlobalPath  string
}

// agentRegistry is the canonical mapping of agents to their skill directories.
// Derived from the supported-agents table in the agent skills scanner design doc.
var agentRegistry = []agentEntry{
	{App: "amp", ProjectPath: ".agents/skills", GlobalPath: ".config/agents/skills"},
	{App: "kimi-cli", ProjectPath: ".agents/skills", GlobalPath: ".config/agents/skills"},
	{App: "replit", ProjectPath: ".agents/skills", GlobalPath: ".config/agents/skills"},
	{App: "universal", ProjectPath: ".agents/skills", GlobalPath: ".config/agents/skills"},
	{App: "antigravity", ProjectPath: ".agents/skills", GlobalPath: ".gemini/antigravity/skills"},
	{App: "augment", ProjectPath: ".augment/skills", GlobalPath: ".augment/skills"},
	{App: "bob", ProjectPath: ".bob/skills", GlobalPath: ".bob/skills"},
	{App: "claude-code", ProjectPath: ".claude/skills", GlobalPath: ".claude/skills"},
	{App: "openclaw", ProjectPath: "skills", GlobalPath: ".openclaw/skills"},
	{App: "cline", ProjectPath: ".agents/skills", GlobalPath: ".agents/skills"},
	{App: "warp", ProjectPath: ".agents/skills", GlobalPath: ".agents/skills"},
	{App: "codebuddy", ProjectPath: ".codebuddy/skills", GlobalPath: ".codebuddy/skills"},
	{App: "codex", ProjectPath: ".agents/skills", GlobalPath: ".codex/skills"},
	{App: "command-code", ProjectPath: ".commandcode/skills", GlobalPath: ".commandcode/skills"},
	{App: "continue", ProjectPath: ".continue/skills", GlobalPath: ".continue/skills"},
	{App: "cortex", ProjectPath: ".cortex/skills", GlobalPath: ".snowflake/cortex/skills"},
	{App: "crush", ProjectPath: ".crush/skills", GlobalPath: ".config/crush/skills"},
	{App: "cursor", ProjectPath: ".agents/skills", GlobalPath: ".cursor/skills"},
	{App: "deepagents", ProjectPath: ".agents/skills", GlobalPath: ".deepagents/agent/skills"},
	{App: "droid", ProjectPath: ".factory/skills", GlobalPath: ".factory/skills"},
	{App: "firebender", ProjectPath: ".agents/skills", GlobalPath: ".firebender/skills"},
	{App: "gemini-cli", ProjectPath: ".agents/skills", GlobalPath: ".gemini/skills"},
	{App: "github-copilot", ProjectPath: ".agents/skills", GlobalPath: ".copilot/skills"},
	{App: "goose", ProjectPath: ".goose/skills", GlobalPath: ".config/goose/skills"},
	{App: "junie", ProjectPath: ".junie/skills", GlobalPath: ".junie/skills"},
	{App: "iflow-cli", ProjectPath: ".iflow/skills", GlobalPath: ".iflow/skills"},
	{App: "kilo", ProjectPath: ".kilocode/skills", GlobalPath: ".kilocode/skills"},
	{App: "kiro-cli", ProjectPath: ".kiro/skills", GlobalPath: ".kiro/skills"},
	{App: "kode", ProjectPath: ".kode/skills", GlobalPath: ".kode/skills"},
	{App: "mcpjam", ProjectPath: ".mcpjam/skills", GlobalPath: ".mcpjam/skills"},
	{App: "mistral-vibe", ProjectPath: ".vibe/skills", GlobalPath: ".vibe/skills"},
	{App: "mux", ProjectPath: ".mux/skills", GlobalPath: ".mux/skills"},
	{App: "opencode", ProjectPath: ".agents/skills", GlobalPath: ".config/opencode/skills"},
	{App: "openhands", ProjectPath: ".openhands/skills", GlobalPath: ".openhands/skills"},
	{App: "pi", ProjectPath: ".pi/skills", GlobalPath: ".pi/agent/skills"},
	{App: "qoder", ProjectPath: ".qoder/skills", GlobalPath: ".qoder/skills"},
	{App: "qwen-code", ProjectPath: ".qwen/skills", GlobalPath: ".qwen/skills"},
	{App: "roo", ProjectPath: ".roo/skills", GlobalPath: ".roo/skills"},
	{App: "trae", ProjectPath: ".trae/skills", GlobalPath: ".trae/skills"},
	{App: "trae-cn", ProjectPath: ".trae/skills", GlobalPath: ".trae-cn/skills"},
	{App: "windsurf", ProjectPath: ".windsurf/skills", GlobalPath: ".codeium/windsurf/skills"},
	{App: "zencoder", ProjectPath: ".zencoder/skills", GlobalPath: ".zencoder/skills"},
	{App: "neovate", ProjectPath: ".neovate/skills", GlobalPath: ".neovate/skills"},
	{App: "pochi", ProjectPath: ".pochi/skills", GlobalPath: ".pochi/skills"},
	{App: "adal", ProjectPath: ".adal/skills", GlobalPath: ".adal/skills"},
}

type adapter struct{}

// New constructs an inventory.Scanner that discovers agent skill directories
// for all agents in the agentRegistry.
func New() inventory.Scanner {
	return &adapter{}
}

// Name returns the stable scanner identifier used in logs and ScanError.
func (a *adapter) Name() string { return scannerName }

// Scan walks each agent's project-local and global skill directories,
// emitting one Item per subdirectory found.
func (a *adapter) Scan(ctx context.Context, cfg inventory.ScanConfig, emit inventory.EmitFunc) error {
	homeDir := cfg.HomeDir
	if homeDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			homeDir = h
		}
	}

	for _, entry := range agentRegistry {
		if cfg.ScopeEnabled(inventory.ScopeProject) && cfg.ProjectDir != "" {
			dir := filepath.Join(cfg.ProjectDir, entry.ProjectPath)
			if err := scanDir(ctx, dir, entry.App, inventory.ScopeProject, emit); err != nil {
				return err
			}
		}
		if cfg.ScopeEnabled(inventory.ScopeSystem) && homeDir != "" {
			dir := filepath.Join(homeDir, entry.GlobalPath)
			if err := scanDir(ctx, dir, entry.App, inventory.ScopeSystem, emit); err != nil {
				return err
			}
		}
	}
	return nil
}

// scanDir lists subdirectories of dir and emits one Item per directory found.
// Missing or unreadable directories are silently skipped.
func scanDir(_ context.Context, dir, app string, scope inventory.Scope, emit inventory.EmitFunc) error {
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
			Name:       e.Name(),
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

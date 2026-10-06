package aitool

import (
	"context"
	"os"
	"path/filepath"
)

// mcpAppSpec describes a coding agent whose discovery is fully determined by
// well-known paths. Agents that need no bespoke logic beyond these paths (and
// optionally a config parser) are modelled as a spec rather than a
// hand-written discoverer.
type mcpAppSpec struct {
	app        string
	appDisplay string

	// agentMarkers are absolute paths (files or directories). The first one
	// that exists emits a system-scoped coding_agent.
	agentMarkers []string

	// systemMCPPaths are absolute paths to system-level MCP config files.
	systemMCPPaths []string

	// projectMCPGlobs are glob patterns, relative to the project directory,
	// matching project-level MCP config files.
	projectMCPGlobs []string

	// instructionFiles are paths, relative to the project directory, reported
	// together as a single project_config when any of them exist.
	instructionFiles []string

	// parse reads one MCP config file. Nil means parseMCPAppConfig, which
	// handles the common {"mcpServers": {...}} JSON layout.
	parse func(path string) (*mcpAppConfig, error)
}

type mcpAppDiscoverer struct {
	spec       mcpAppSpec
	projectDir string
	config     DiscoveryConfig
}

func newMCPAppDiscoverer(config DiscoveryConfig, spec mcpAppSpec) *mcpAppDiscoverer {
	if spec.parse == nil {
		spec.parse = parseMCPAppConfig
	}
	return &mcpAppDiscoverer{spec: spec, projectDir: config.ProjectDir, config: config}
}

func (d *mcpAppDiscoverer) Name() string { return d.spec.appDisplay + " Config" }
func (d *mcpAppDiscoverer) App() string  { return d.spec.app }

func (d *mcpAppDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		for _, path := range d.spec.systemMCPPaths {
			if err := d.emitMCPFile(path, AIToolScopeSystem, handler); err != nil {
				return err
			}
		}

		if marker := firstExistingPath(d.spec.agentMarkers); marker != "" {
			if err := handler(newCodingAgent(d.spec.app, d.spec.appDisplay, marker)); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(AIToolScopeProject) && d.projectDir != "" {
		return d.processProjectConfigs(handler)
	}

	return nil
}

func (d *mcpAppDiscoverer) processProjectConfigs(handler AIToolHandlerFn) error {
	for _, pattern := range d.spec.projectMCPGlobs {
		matches, err := filepath.Glob(filepath.Join(d.projectDir, pattern))
		if err != nil {
			continue
		}
		for _, path := range matches {
			if err := d.emitMCPFile(path, AIToolScopeProject, handler); err != nil {
				return err
			}
		}
	}

	var instructionFiles []string
	for _, rel := range d.spec.instructionFiles {
		path := filepath.Join(d.projectDir, rel)
		if _, err := os.Stat(path); err == nil {
			instructionFiles = append(instructionFiles, path)
		}
	}

	if len(instructionFiles) == 0 {
		return nil
	}

	tool := &AITool{
		Name:       d.spec.appDisplay,
		Type:       AIToolTypeProjectConfig,
		Scope:      AIToolScopeProject,
		App:        d.spec.app,
		AppDisplay: d.spec.appDisplay,
		ConfigPath: d.projectDir,
		Agent: &AgentConfig{
			InstructionFiles: instructionFiles,
		},
	}
	tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
	tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)

	return handler(tool)
}

func (d *mcpAppDiscoverer) emitMCPFile(path string, scope AIToolScope, handler AIToolHandlerFn) error {
	if path == "" {
		return nil
	}
	cfg, err := d.spec.parse(path)
	if err != nil {
		return nil
	}
	return emitMCPServers(cfg, path, scope, d.spec.app, d.spec.appDisplay, handler)
}

// newCodingAgent builds a system-scoped coding_agent rooted at configPath.
func newCodingAgent(app, appDisplay, configPath string) *AITool {
	agent := &AITool{
		Name:       appDisplay,
		Type:       AIToolTypeCodingAgent,
		Scope:      AIToolScopeSystem,
		App:        app,
		AppDisplay: appDisplay,
		ConfigPath: configPath,
		Agent:      &AgentConfig{},
	}
	agent.ID = generateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
	agent.SourceID = generateSourceID(agent.App, agent.ConfigPath)
	return agent
}

// firstExistingPath returns the first non-empty path that exists, or "".
func firstExistingPath(paths []string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// resolveHomeDir returns config.HomeDir, falling back to the current user's
// home directory when it is not overridden.
func resolveHomeDir(config DiscoveryConfig) (string, error) {
	if config.HomeDir != "" {
		return config.HomeDir, nil
	}
	return os.UserHomeDir()
}

// envPath joins elem onto the directory named by the environment variable
// key. It returns "" when the variable is unset so callers never probe a
// path relative to the working directory (e.g. %APPDATA% on Linux/macOS).
func envPath(key string, elem ...string) string {
	base := os.Getenv(key)
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base}, elem...)...)
}

// envDirOr returns the directory named by the environment variable key when
// it is set, otherwise fallback. Used for agents that relocate their home via
// an env var (e.g. CODEX_HOME, COPILOT_HOME).
func envDirOr(key, fallback string) string {
	if dir := os.Getenv(key); dir != "" {
		return dir
	}
	return fallback
}

// vscodeUserDataDirs returns the per-OS VS Code user-data directories.
// Linux:   ~/.config/Code/User/
// macOS:   ~/Library/Application Support/Code/User/
// Windows: %APPDATA%\Code\User\
func vscodeUserDataDirs(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".config", "Code", "User"),
		filepath.Join(homeDir, "Library", "Application Support", "Code", "User"),
		envPath("APPDATA", "Code", "User"),
	}
}

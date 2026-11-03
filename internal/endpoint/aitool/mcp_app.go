package aitool

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// mcpAppSpec describes a coding agent that vet finds by its known paths
// alone. Such an agent needs a spec and an optional parser, not a discoverer
// of its own.
type mcpAppSpec struct {
	app        string
	appDisplay string

	// agentMarkers are absolute paths of files or folders. The first one
	// that exists gives a system coding agent.
	agentMarkers []string

	// installMarkers are the documented install locations, such as an app
	// bundle. One that exists gives the agent app_bundle evidence.
	installMarkers []string

	// systemMCPPaths are absolute paths of system MCP config files.
	systemMCPPaths []string

	// projectMCPGlobs are glob patterns, relative to the project folder, of
	// project MCP config files.
	projectMCPGlobs []string

	// instructionFiles are paths, relative to the project folder. The files
	// that exist give one project config item.
	instructionFiles []string

	// parse reads one MCP config file. Nil means parseMCPAppConfig, which
	// reads the {"mcpServers": {...}} JSON layout.
	parse func(path string) (*mcpAppConfig, error)
}

type mcpAppDiscoverer struct {
	spec   mcpAppSpec
	config DiscoveryConfig
}

func newMCPAppDiscoverer(config DiscoveryConfig, spec mcpAppSpec) *mcpAppDiscoverer {
	if spec.parse == nil {
		spec.parse = parseMCPAppConfig
	}
	return &mcpAppDiscoverer{spec: spec, config: config}
}

func (d *mcpAppDiscoverer) Name() string { return d.spec.appDisplay + " Config" }
func (d *mcpAppDiscoverer) App() string  { return d.spec.app }

func (d *mcpAppDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(inventory.ScopeSystem) {
		for _, path := range d.spec.systemMCPPaths {
			if err := d.emitMCPFile(path, inventory.ScopeSystem, handler); err != nil {
				return err
			}
		}

		if marker := firstExistingPath(d.spec.agentMarkers); marker != "" {
			agent := newCodingAgent(d.spec.app, d.spec.appDisplay, marker)
			markAppBundle(agent, d.spec.installMarkers)
			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(inventory.ScopeProject) && d.config.ProjectDir != "" {
		return d.processProjectConfigs(handler)
	}

	return nil
}

func (d *mcpAppDiscoverer) processProjectConfigs(handler AIToolHandlerFn) error {
	projectDir := d.config.ProjectDir
	for _, pattern := range d.spec.projectMCPGlobs {
		matches, err := filepath.Glob(filepath.Join(projectDir, pattern))
		if err != nil {
			log.Warnf("endpoint: glob %s: %v", pattern, err)
			continue
		}
		for _, path := range matches {
			if err := d.emitMCPFile(path, inventory.ScopeProject, handler); err != nil {
				return err
			}
		}
	}

	var instructionFiles []string
	for _, rel := range d.spec.instructionFiles {
		path := filepath.Join(projectDir, rel)
		if _, err := os.Stat(path); err == nil {
			instructionFiles = append(instructionFiles, path)
		}
	}
	if len(instructionFiles) == 0 {
		return nil
	}

	item := newItem(inventory.KindProjectConfig, inventory.ScopeProject, d.spec.app, d.spec.appDisplay, d.spec.appDisplay, projectDir)
	item.Agent = &inventory.AgentDetail{InstructionFiles: instructionFiles}
	return handler(item)
}

func (d *mcpAppDiscoverer) emitMCPFile(path string, scope inventory.Scope, handler AIToolHandlerFn) error {
	if path == "" {
		return nil
	}
	cfg, err := d.spec.parse(path)
	if err != nil {
		// A missing file is the common case. The parser logs a broken file.
		return nil
	}
	return emitMCPServers(cfg, path, scope, d.spec.app, d.spec.appDisplay, handler)
}

// firstExistingPath returns the first path that is not empty and that
// exists, or "".
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

// envPath joins elem to the folder in the environment variable key. It
// returns "" when the variable is not set. Without this, a path such as
// %APPDATA%\Zed on Linux becomes a path relative to the working folder.
func envPath(key string, elem ...string) string {
	base := os.Getenv(key)
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base}, elem...)...)
}

// unixPath joins elem under the root of the file system on macOS and Linux.
// It returns "" on Windows, where a root path with no drive letter points
// to the current drive.
func unixPath(elem ...string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return filepath.Join(append([]string{"/"}, elem...)...)
}

// envDirOr returns the folder in the environment variable key, or fallback
// when the variable is not set. Codex and Copilot CLI move their config
// folder with such a variable.
func envDirOr(key, fallback string) string {
	if dir := os.Getenv(key); dir != "" {
		return dir
	}
	return fallback
}

// vscodeUserDataDirs returns the VS Code user data folders of each OS:
// ~/.config/Code/User on Linux, ~/Library/Application Support/Code/User on
// macOS and %APPDATA%\Code\User on Windows. The Windows entry is "" when
// APPDATA is not set.
func vscodeUserDataDirs(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".config", "Code", "User"),
		filepath.Join(homeDir, "Library", "Application Support", "Code", "User"),
		envPath("APPDATA", "Code", "User"),
	}
}

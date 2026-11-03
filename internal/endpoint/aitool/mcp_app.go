package aitool

import (
	"context"
	"errors"
	"io/fs"
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
		// The pattern applies under the project folder only, so a "[" or
		// a "*" in the folder name does not act as a wildcard.
		matches, err := fs.Glob(os.DirFS(projectDir), filepath.ToSlash(pattern))
		if err != nil {
			log.Warnf("endpoint: glob %s: %v", pattern, err)
			continue
		}
		for _, rel := range matches {
			path := filepath.Join(projectDir, filepath.FromSlash(rel))
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
		// A missing file is the common case, and the parser logs a broken
		// file. A file that vet cannot read, such as one of another user,
		// gets a log line, so the audit does not miss its servers silently.
		var pe *fs.PathError
		if errors.As(err, &pe) && !errors.Is(err, fs.ErrNotExist) {
			log.Warnf("endpoint: read %s: %v", path, err)
		}
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
// folder with such a variable. The variable belongs to the user of the
// process. With --all-users, vet reads the home of each other user at
// fallback, so it does not read the folder of one user for each user.
func envDirOr(config DiscoveryConfig, key, fallback string) string {
	if !ownHome(config) {
		return fallback
	}
	if dir := os.Getenv(key); dir != "" {
		return dir
	}
	return fallback
}

// ownHome reports whether the discovery reads the home of the user of the
// process.
func ownHome(c DiscoveryConfig) bool {
	if c.HomeDir == "" {
		return true
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	// On macOS, /var/root and /private/var/root are one folder, so vet
	// compares the folders and not the paths.
	own, err := os.Stat(h)
	if err != nil {
		return false
	}
	scanned, err := os.Stat(c.HomeDir)
	return err == nil && os.SameFile(own, scanned)
}

// appDataPath joins elem to the roaming application data folder of the
// home that the discovery reads: %APPDATA% for the user who runs vet, and
// AppData\Roaming under the home of another user on Windows. With
// --all-users, the APPDATA of the user who runs vet is not the folder of the
// other users. It returns "" when there is no such folder.
func appDataPath(config DiscoveryConfig, homeDir string, elem ...string) string {
	if ownHome(config) {
		return envPath("APPDATA", elem...)
	}
	if runtime.GOOS != "windows" {
		return ""
	}
	return filepath.Join(append([]string{homeDir, "AppData", "Roaming"}, elem...)...)
}

// vscodeUserDataDirs returns the VS Code user data folders of each OS:
// ~/.config/Code/User on Linux, ~/Library/Application Support/Code/User on
// macOS and %APPDATA%\Code\User on Windows. The Windows entry can be "".
func vscodeUserDataDirs(config DiscoveryConfig, homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".config", "Code", "User"),
		filepath.Join(homeDir, "Library", "Application Support", "Code", "User"),
		appDataPath(config, homeDir, "Code", "User"),
	}
}

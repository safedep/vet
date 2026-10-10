// Package endpoint is the source of vet endpoint audit. It reads this
// machine: the AI tools, MCP servers, agent skills and editor plugins as
// inventory, the IDE extensions and the global npm packages as packages,
// and the agent and editor config files for the controls. vet scan never
// uses it, so a project scan never reads $HOME.
package endpoint

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
	"github.com/safedep/vet/v2/internal/endpoint/inventory/scanners"
	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the source.
const Name = "endpoint"

// Options configure the source.
type Options struct {
	// AllUsers reads the home directory of every user. It needs root.
	AllUsers bool `json:"all_users"`
	// Projects are folders of repositories. vet reads the files of each one
	// that can run code or hide it: agent and editor configs, build configs,
	// assets and scripts.
	Projects []string `json:"projects,omitempty"`
}

// System is what the source reads from the machine. Tests replace it.
type System struct {
	Hostname func() (string, error)
	// Home is the home directory of the current user.
	Home func() (string, error)
	// Homes lists the home directories of every user.
	Homes func() ([]string, error)
	// Privileged reports that the process can read every home directory.
	Privileged func() bool
	// GlobalRoots lists the system-wide npm global package directories.
	GlobalRoots func() []string
	// Scanners builds the inventory scanners.
	Scanners func() ([]inventory.Scanner, error)
}

// DefaultSystem reads the real machine.
func DefaultSystem() System {
	return System{
		Hostname:    os.Hostname,
		Home:        os.UserHomeDir,
		Homes:       userHomes,
		Privileged:  privileged,
		GlobalRoots: systemGlobalRoots,
		Scanners:    func() ([]inventory.Scanner, error) { return scanners.Build(nil) },
	}
}

// ErrNeedsRoot is the error of --all-users without root.
var ErrNeedsRoot = errors.New("endpoint: reading every user needs root")

// Source yields one artifact: the machine.
type Source struct {
	opts Options
	sys  System
}

// New returns the source.
func New(o Options, sys System) *Source { return &Source{opts: o, sys: sys} }

// Key returns the target key of the machine, endpoint:<hostname>.
func Key(hostname string) string { return "endpoint:" + strings.ToLower(hostname) }

// Artifacts yields the machine.
func (s *Source) Artifacts(ctx context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		a, err := s.artifact(ctx)
		yield(a, err)
	}
}

func (s *Source) artifact(ctx context.Context) (plugin.Artifact, error) {
	host, err := s.sys.Hostname()
	if err != nil {
		return plugin.Artifact{}, fmt.Errorf("endpoint: hostname: %w", err)
	}
	homes, err := s.homes()
	if err != nil {
		return plugin.Artifact{}, err
	}
	root := fsRoot(homes[0])
	a := plugin.Artifact{
		Kind: plugin.ArtifactEndpoint, Label: "endpoint " + host, Key: Key(host),
		Path: root, Root: os.DirFS(root),
	}
	files := map[string]bool{}
	for _, home := range homes {
		items, err := s.inventory(ctx, home)
		if err != nil {
			return plugin.Artifact{}, err
		}
		for _, it := range items {
			a.Inventory = append(a.Inventory, toRecord(it))
			if p := configFile(it); p != "" {
				files[p] = true
			}
			if m := extensionManifest(it); m != nil {
				a.Manifests = mergeManifest(a.Manifests, m)
			}
		}
		for _, f := range agentfiles.HomeFiles {
			files[filepath.Join(home, filepath.FromSlash(f))] = true
		}
		a.Manifests = append(a.Manifests, globalPackages(userGlobalRoots(home))...)
	}
	if s.opts.AllUsers {
		a.Manifests = append(a.Manifests, globalPackages(s.sys.GlobalRoots())...)
	}
	for _, root := range s.npmRoots(homes) {
		for _, f := range hiddencode.EntryFiles(filepath.ToSlash(root)) {
			files[filepath.FromSlash(f)] = true
		}
	}
	projects, err := CheckProjects(homes[0], s.opts.Projects)
	if err != nil {
		return plugin.Artifact{}, err
	}
	walked := map[string]bool{}
	for _, dir := range projects {
		if err := projectFiles(ctx, dir, files, walked); err != nil {
			return plugin.Artifact{}, err
		}
	}
	a.Include = include(root, files)
	sortManifests(a.Manifests)
	return a, nil
}

func (s *Source) homes() ([]string, error) {
	if !s.opts.AllUsers {
		h, err := s.sys.Home()
		if err != nil {
			return nil, fmt.Errorf("endpoint: home directory: %w", err)
		}
		return []string{h}, nil
	}
	if !s.sys.Privileged() {
		return nil, ErrNeedsRoot
	}
	homes, err := s.sys.Homes()
	if err != nil {
		return nil, err
	}
	if len(homes) == 0 {
		return nil, errors.New("endpoint: no home directory found")
	}
	sort.Strings(homes)
	return homes, nil
}

func (s *Source) inventory(ctx context.Context, home string) ([]*inventory.Item, error) {
	scs, err := s.sys.Scanners()
	if err != nil {
		return nil, err
	}
	cfg := inventory.ScanConfig{HomeDir: home, Scopes: []inventory.Scope{inventory.ScopeSystem}}
	var out []*inventory.Item
	for _, sc := range scs {
		err := sc.Scan(ctx, cfg, func(it *inventory.Item) error {
			out = append(out, it)
			return nil
		})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			// One broken scanner does not hide the others.
			log.Warnf("endpoint: %s: %v", sc.Name(), err)
		}
	}
	return out, nil
}

// configFile returns the config file of an item that the controls read:
// the file of an MCP server or of an agent. Extensions and skills have no
// such file.
func configFile(it *inventory.Item) string {
	switch it.Kind {
	case inventory.KindMCPServer, inventory.KindCodingAgent, inventory.KindProjectConfig, inventory.KindAgentPlugin:
		return it.ConfigPath
	}
	return ""
}

// include returns the paths relative to root of the files that exist.
func include(root string, files map[string]bool) []string {
	var out []string
	for f := range files {
		info, err := os.Stat(f)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		rel, err := filepath.Rel(root, f)
		if err != nil || strings.HasPrefix(rel, "..") {
			// A file on another volume than the home directory, on Windows.
			log.Warnf("endpoint: %s is outside %s, so vet does not check it", f, root)
			continue
		}
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

// npmRoots returns the global package folders whose npm entry scripts vet
// checks: those of the users, and with --all-users those of the machine.
// PolinRider overwrites npm/lib/cli.js, so each npm or npx command starts
// the malware again.
func (s *Source) npmRoots(homes []string) []string {
	var out []string
	for _, home := range homes {
		out = append(out, userGlobalRoots(home)...)
	}
	if s.opts.AllUsers {
		out = append(out, s.sys.GlobalRoots()...)
	}
	return out
}

// projectSkipDirs are the folders that hold no file of the project itself,
// or that are too large to walk on each audit.
var projectSkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, ".gradle": true, "target": true, ".next": true, ".cache": true, ".npm": true,
}

// maxProjectFiles caps the files that --projects adds for one folder.
const maxProjectFiles = 100000

// projectFiles adds the files of the repositories under dir that can run
// code or hide it. A worm that spreads to every repository on a machine
// changes these files. The source files stay out, so a large folder of
// repositories stays fast to audit.
// walked holds the real path of each folder that the walk entered, so a
// link back to a parent folder does not loop.
func projectFiles(ctx context.Context, dir string, files, walked map[string]bool) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || walked[real] {
		return nil
	}
	walked[real] = true
	added := 0
	// The walk reads the real folder, and names each file by its path under
	// dir: the controls read the name of a linked folder, such as .vscode.
	return filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
		if rel, relErr := filepath.Rel(real, p); relErr == nil {
			p = filepath.Join(dir, rel)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// An unreadable folder does not stop the audit.
			log.Warnf("endpoint: %s: %v", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != dir && projectSkipDirs[d.Name()] && !repository(p) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// An editor follows a link such as .vscode or .vscode/tasks.json.
			info, err := os.Stat(p)
			switch {
			case err != nil:
				return nil
			case info.IsDir() && agentfiles.ConfigDirs[d.Name()]:
				return projectFiles(ctx, p, files, walked)
			case !info.Mode().IsRegular():
				return nil
			}
		} else if !d.Type().IsRegular() {
			return nil
		}
		if !projectFile(filepath.ToSlash(p)) {
			return nil
		}
		if added >= maxProjectFiles {
			log.Warnf("endpoint: --projects %s holds more than %d files to check. vet checks the first %d", dir, maxProjectFiles, maxProjectFiles)
			return fs.SkipAll
		}
		files[p] = true
		added++
		return nil
	})
}

// repository reports a folder that holds a git repository. A repository
// can have the name of a skipped folder, such as target or venv.
func repository(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// CheckProjects returns the absolute path of each --projects folder, or an
// error for a folder that does not exist, is not a folder, or is on another
// volume than home. The audit
// reads files by their path from the root of the file system, so a
// relative path would match no file.
func CheckProjects(home string, dirs []string) ([]string, error) {
	vol := filepath.VolumeName(home)
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("--projects %s: %w", dir, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("--projects %s: %w", dir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("--projects %s: not a folder", dir)
		}
		// The audit reads one file system, the one of the home directory.
		// On Windows a folder on another volume gives no finding at all.
		if v := filepath.VolumeName(abs); !strings.EqualFold(v, vol) {
			return nil, fmt.Errorf("--projects %s: the folder is not on volume %s of the home directory", dir, vol)
		}
		out = append(out, abs)
	}
	return out, nil
}

// projectFile reports a file of a repository that the agent-config or the
// hidden-code controls read, other than a source file.
func projectFile(p string) bool {
	if _, ok := agentfiles.Classify(p); ok {
		return true
	}
	c, ok := hiddencode.Classify(p)
	return ok && c != hiddencode.Source
}

// fsRoot returns the root of the file system that holds path: "/" or a
// Windows volume such as "C:\".
func fsRoot(path string) string {
	if v := filepath.VolumeName(path); v != "" {
		return v + string(filepath.Separator)
	}
	return string(filepath.Separator)
}

func userHomes() ([]string, error) {
	var parents []string
	switch runtime.GOOS {
	case "windows":
		parents = []string{filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")}
	case "darwin":
		parents = []string{"/Users"}
	default:
		parents = []string{"/home"}
	}
	var out []string
	for _, p := range parents {
		entries, err := os.ReadDir(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		for _, e := range entries {
			switch strings.ToLower(e.Name()) {
			case "shared", "public", "default", "default user", "all users":
				continue
			}
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				out = append(out, filepath.Join(p, e.Name()))
			}
		}
	}
	if runtime.GOOS != "windows" {
		root := "/root"
		if runtime.GOOS == "darwin" {
			root = "/var/root"
		}
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			out = append(out, root)
		}
	}
	return out, nil
}

func sortManifests(ms []*model.Manifest) {
	sort.Slice(ms, func(i, j int) bool { return ms[i].Path < ms[j].Path })
}

var _ plugin.Source = (*Source)(nil)

package lockfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/packagelockjson"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// IDInstalledNotLocked is the control id of an installed npm package that
// the lockfile of its project does not list.
const IDInstalledNotLocked = "installed-not-locked"

var installedInfo = plugin.ControlInfo{
	ID: IDInstalledNotLocked, Family: finding.FamilyLockfile, Severity: finding.SeverityMedium,
	Title:       "Installed package that the lockfile does not list",
	Description: "node_modules holds a package, or a version of a package, that the lockfile of the project does not list. A stale install gives this result, and so does a package that someone added to node_modules by hand.",
}

// locked holds the npm packages of the lockfiles of one project directory.
type locked struct {
	// dir is the directory of the lockfiles.
	dir      string
	keys     map[model.PackageKey]bool
	versions map[model.PackageKey][]string
	// anyVersion holds the paths, relative to dir, of the npm lockfile
	// entries that the extractor gives no npm package for, such as a git or
	// a file dependency. The control cannot compare the version of these.
	anyVersion map[string]bool
}

func newLocked(dir string) *locked {
	return &locked{dir: dir, keys: map[model.PackageKey]bool{}, versions: map[model.PackageKey][]string{}, anyVersion: map[string]bool{}}
}

// lockIndex maps a project directory to its locked npm packages. The
// control builds it once for each scan state.
type lockIndex struct {
	mu    sync.Mutex
	state plugin.State
	dirs  map[string]*locked
}

func (x *lockIndex) of(ctx context.Context, s plugin.State, root fs.FS) (map[string]*locked, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.state == s && x.dirs != nil {
		return x.dirs, nil
	}
	dirs := map[string]*locked{}
	for m, err := range s.Manifests(ctx) {
		if err != nil {
			return nil, err
		}
		if m.Kind != model.ManifestKindLockfile || m.Ecosystem != model.EcosystemNpm {
			continue
		}
		dir := path.Dir(m.Path)
		l := dirs[dir]
		if l == nil {
			l = newLocked(dir)
			dirs[dir] = l
		}
		for _, p := range m.Packages {
			l.keys[p.ID.Key()] = true
			name := p.ID.NameKey()
			if !slices.Contains(l.versions[name], p.ID.Version()) {
				l.versions[name] = append(l.versions[name], p.ID.Version())
			}
		}
		if m.Extractor == packagelockjson.Name && root != nil {
			if err := l.addUnversioned(root, m.Path); err != nil {
				return nil, err
			}
		}
	}
	x.state, x.dirs = s, dirs
	return dirs, nil
}

// addUnversioned reads an npm lockfile and records the entries that the
// extractor gave no npm package for.
func (l *locked) addUnversioned(root fs.FS, file string) error {
	data, err := fs.ReadFile(root, file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	var lf npmLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return fmt.Errorf("decode %s: %w", file, err)
	}
	entries := map[string]entry{}
	maps.Copy(entries, lf.Packages)
	if len(lf.Packages) == 0 {
		flatten("", lf.Dependencies, entries)
	}
	for p, e := range entries {
		name := nameOf(p)
		if name == "" {
			continue
		}
		if id, err := model.NewPackageVersion(model.EcosystemNpm, name, e.Version); err == nil && l.keys[id.Key()] {
			continue
		}
		l.anyVersion[p] = true
	}
	return nil
}

// installed checks the packages of an installed npm manifest against the
// lockfiles of its project: the directory that holds the outer
// node_modules, or its nearest parent with an npm lockfile. A project with
// no npm lockfile has no verdict.
func (c *Control) installed(ctx context.Context, m *model.Manifest, s plugin.State) ([]finding.Finding, error) {
	project, ok := projectDir(m.Path)
	if !ok || m.Ecosystem != model.EcosystemNpm {
		return nil, nil
	}
	dirs, err := c.locks.of(ctx, s, m.Root)
	if err != nil {
		return nil, err
	}
	l := nearest(dirs, project)
	if l == nil {
		return nil, nil
	}
	var out []finding.Finding
	for _, p := range m.Packages {
		if l.keys[p.ID.Key()] || l.anyVersion[l.entry(m.Path)] {
			continue
		}
		title := fmt.Sprintf("%s is installed, and the lockfile does not list it", p.ID)
		if vs := l.versions[p.ID.NameKey()]; len(vs) > 0 {
			title = fmt.Sprintf("%s is installed, and the lockfile has %s", p.ID, strings.Join(vs, ", "))
		}
		f := finding.ForPackage(finding.Meta{
			ControlID: IDInstalledNotLocked, Family: installedInfo.Family, Severity: installedInfo.Severity,
			Confidence: finding.ConfidenceMedium, Title: title, Description: installedInfo.Description,
		}, m.Path, p, finding.Key{})
		f.Remediation = &finding.Remediation{
			Summary: "Delete node_modules and install again from the lockfile, for example with npm ci. Find out how the package got there if the lockfile did not put it there.",
		}
		out = append(out, f)
	}
	return out, nil
}

// entry returns the lockfile entry path of the package.json of an installed
// package, as in node_modules/a/node_modules/b.
func (l *locked) entry(manifest string) string {
	dir := path.Dir(manifest)
	if l.dir == "." {
		return dir
	}
	return strings.TrimPrefix(dir, l.dir+"/")
}

// nearest returns the lockfiles of the directory or of its nearest parent
// that has one. A workspace member has no lockfile of its own. The root
// lockfile lists its node_modules.
func nearest(dirs map[string]*locked, dir string) *locked {
	for {
		if l := dirs[dir]; l != nil {
			return l
		}
		if dir == "." || dir == "/" {
			return nil
		}
		dir = path.Dir(dir)
	}
}

// projectDir returns the directory that holds the outer node_modules of a
// path, with "/".
func projectDir(p string) (string, bool) {
	parts := strings.Split(p, "/")
	i := slices.Index(parts, "node_modules")
	if i < 0 {
		return "", false
	}
	if i == 0 {
		return ".", true
	}
	return strings.Join(parts[:i], "/"), true
}

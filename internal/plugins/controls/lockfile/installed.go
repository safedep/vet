package lockfile

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/finding"
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
	keys     map[model.PackageKey]bool
	versions map[model.PackageKey][]string
}

// lockIndex maps a project directory to its locked npm packages. The
// control builds it once for each scan state.
type lockIndex struct {
	mu    sync.Mutex
	state plugin.State
	dirs  map[string]*locked
}

func (x *lockIndex) of(ctx context.Context, s plugin.State) (map[string]*locked, error) {
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
			l = &locked{keys: map[model.PackageKey]bool{}, versions: map[model.PackageKey][]string{}}
			dirs[dir] = l
		}
		for _, p := range m.Packages {
			l.keys[p.ID.Key()] = true
			name := p.ID.NameKey()
			if !slices.Contains(l.versions[name], p.ID.Version()) {
				l.versions[name] = append(l.versions[name], p.ID.Version())
			}
		}
	}
	x.state, x.dirs = s, dirs
	return dirs, nil
}

// installed checks the packages of an installed npm manifest against the
// lockfiles of its project: the directory that holds the outer
// node_modules. A project with no npm lockfile has no verdict.
func (c *Control) installed(ctx context.Context, m *model.Manifest, s plugin.State) ([]finding.Finding, error) {
	project, ok := projectDir(m.Path)
	if !ok || m.Ecosystem != model.EcosystemNpm {
		return nil, nil
	}
	dirs, err := c.locks.of(ctx, s)
	if err != nil {
		return nil, err
	}
	l := dirs[project]
	if l == nil {
		return nil, nil
	}
	var out []finding.Finding
	for _, p := range m.Packages {
		if l.keys[p.ID.Key()] {
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

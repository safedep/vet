package codeusage

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/code/projectgraph/modules"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/model"
)

// pythonEnvironment is the installed code of a Python project: each
// site-packages directory of its virtual environment, with the
// distributions that the .dist-info directories describe, and the standard
// library of the interpreter of the environment. vet never runs pip and
// downloads nothing.
type pythonEnvironment struct {
	// dir is the directory that the environment belongs to: the scan root,
	// or the directory of a manifest.
	dir   string
	sites []pythonSite
	// local is true when a virtual environment under dir gives a site. The
	// environment that VIRTUAL_ENV names belongs to the whole target, not
	// to one directory.
	local bool
	// stdlib is the Lib directory of the interpreter of the first virtual
	// environment, and version its version, or "" when vet did not find it.
	stdlib  string
	version string
}

// pythonSite is one site-packages directory.
type pythonSite struct {
	dir   string
	dists []modules.Distribution
}

// venvNames are the directories under the target that hold a virtual
// environment, when VIRTUAL_ENV names none.
var venvNames = []string{".venv", "venv", "env"}

// readPythonEnvironment finds the environment of the project under dir:
// the virtual environment that VIRTUAL_ENV names, and each one under dir
// with a pyvenv.cfg.
func readPythonEnvironment(dir string) *pythonEnvironment {
	env := &pythonEnvironment{dir: dir}
	for _, venv := range venvDirs(dir) {
		before := len(env.sites)
		for _, site := range venvSitePackages(venv.path) {
			env.addSite(site)
		}
		if venv.local && len(env.sites) > before {
			env.local = true
		}
		if env.stdlib == "" {
			env.stdlib, env.version = venvStdlib(venv.path)
		}
	}
	return env
}

// venvDir is a virtual environment: its path, and whether it is under the
// directory of the project.
type venvDir struct {
	path  string
	local bool
}

// venvDirs returns the virtual environments of the project: the one that
// VIRTUAL_ENV names, then each directory of venvNames under dir that holds
// a pyvenv.cfg.
func venvDirs(dir string) []venvDir {
	var out []venvDir
	add := func(venv string, local bool) {
		if fileExists(filepath.Join(venv, "pyvenv.cfg")) {
			out = append(out, venvDir{path: venv, local: local})
		}
	}
	if v := os.Getenv("VIRTUAL_ENV"); v != "" && filepath.IsAbs(v) {
		add(v, false)
	}
	for _, name := range venvNames {
		add(filepath.Join(dir, name), true)
	}
	return out
}

// venvSitePackages returns the site-packages directories of a virtual
// environment: lib/python3.X/site-packages on a POSIX system, or
// lib/pypy3.X/site-packages for PyPy, and Lib/site-packages on Windows. A
// lib64 that is a link to lib counts once.
func venvSitePackages(venv string) []string {
	var out []string
	seen := map[string]bool{}
	for _, pattern := range []string{"lib/python*/site-packages", "lib/pypy*/site-packages", "lib64/python*/site-packages", "Lib/site-packages"} {
		matches, err := filepath.Glob(filepath.Join(venv, filepath.FromSlash(pattern)))
		if err != nil {
			continue
		}
		for _, m := range matches {
			real, err := filepath.EvalSymlinks(m)
			if err != nil || seen[real] {
				continue
			}
			seen[real] = true
			out = append(out, m)
		}
	}
	return out
}

// venvStdlib returns the Lib directory of the interpreter of a virtual
// environment and its version, from the home and the version lines of
// pyvenv.cfg. On a POSIX system the home is the bin directory of the
// interpreter, and its standard library is in lib/python3.X next to it. On
// Windows the home is the directory of python.exe, and the library is in
// Lib under it.
func venvStdlib(venv string) (string, string) {
	data, err := os.ReadFile(filepath.Join(venv, "pyvenv.cfg"))
	if err != nil {
		return "", ""
	}
	var home, version string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key, value = strings.TrimSpace(key), strings.TrimSpace(value); key {
		case "home":
			home = value
		case "version", "version_info":
			if version == "" {
				version = pythonVersion(value)
			}
		}
	}
	if home == "" || version == "" {
		return "", ""
	}
	major, _, _ := strings.Cut(version, ".")
	minor := strings.Join(strings.Split(version, ".")[:2], ".")
	for _, lib := range []string{filepath.Join(home, "..", "lib", "python"+minor), filepath.Join(home, "..", "lib", "python"+major), filepath.Join(home, "Lib")} {
		if fileExists(filepath.Join(lib, "os.py")) {
			return filepath.Clean(lib), version
		}
	}
	return "", ""
}

// pythonVersion returns the X.Y.Z of a version line of pyvenv.cfg, as
// 3.12.3 for "3.12.3" or "3.12.3.final.0", or "" for another form.
func pythonVersion(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return ""
	}
	parts = parts[:min(3, len(parts))]
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return ""
		}
	}
	return strings.Join(parts, ".")
}

// addSite reads the distributions of a site-packages directory.
func (env *pythonEnvironment) addSite(dir string) {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return
	}
	dists, problems := modules.PythonDistributions(os.DirFS(dir))
	for _, p := range problems {
		log.Debugf("codeusage: %s: %s", filepath.Join(dir, p.Path), p.Text)
	}
	env.sites = append(env.sites, pythonSite{dir: dir, dists: dists})
}

// unit returns the unit of a package: the distribution of its name at its
// version in a site-packages directory. The call paths of another version
// prove nothing, so another version gives no unit. An editable install is
// the project itself, so it gives none either. The root of the unit is the
// site-packages directory, so a path in the unit is the path that Python
// imports, and the directories of the unit are the packages and the
// modules of the distribution, as its RECORD lists them.
func (env *pythonEnvironment) unit(id model.PackageVersion) (Unit, bool) {
	for _, s := range env.sites {
		for _, d := range s.dists {
			pv, err := model.NewPackageVersion(model.EcosystemPyPI, d.Name, d.Version)
			if err != nil || !pv.Equal(id) || d.Editable {
				continue
			}
			roots := d.Roots()
			if len(roots) == 0 {
				roots = topLevelDirs(s.dir, d)
			}
			if len(roots) == 0 {
				continue
			}
			u := Unit{Key: d.Unit(), Root: s.dir, Dir: filepath.Join(s.dir, filepath.FromSlash(roots[0]))}
			for _, r := range roots[1:] {
				u.Dirs = append(u.Dirs, filepath.Join(s.dir, filepath.FromSlash(r)))
			}
			return u, true
		}
	}
	return Unit{}, false
}

// topLevelDirs returns the package directories and the modules of the
// top-level names of a distribution with no RECORD, as they are on the
// disk. A name of top_level.txt is one path element, or it could read code
// from outside the site-packages directory.
func topLevelDirs(site string, d modules.Distribution) []string {
	var out []string
	for _, top := range d.TopLevel {
		if !pathElement(top) {
			continue
		}
		switch {
		case fileExists(filepath.Join(site, top, "__init__.py")):
			out = append(out, top)
		case fileExists(filepath.Join(site, top+".py")):
			out = append(out, top+".py")
		}
	}
	return out
}

// stdlibUnit returns the unit of the standard library of the interpreter
// of the environment, as python:std@3.12.3 for its Lib directory.
func (env *pythonEnvironment) stdlibUnit() (Unit, bool) {
	if env.stdlib == "" {
		return Unit{}, false
	}
	return Unit{Key: "python:std@" + env.version, Dir: env.stdlib}, true
}

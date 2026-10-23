package pnpmlock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/lockmeta"
	"github.com/safedep/vet/v2/model"
)

// packageManagerField is the field of package.json that sets the version
// of pnpm. pnpm 10 and later lock pnpm itself, with the packages that it
// installs for itself, in the first document of the lockfile.
const packageManagerField = "packageManager"

var packageManagerLine = regexp.MustCompile(`^\s*"packageManager"\s*:`)

// declarePackageManager marks each package that the lockfile document
// installs for the package manager with the "packageManager" field of the
// package.json next to the lockfile. A fix of such a package edits that
// field, not the lockfile. A document with no packageManagerDependencies,
// or a project with no such field, marks nothing.
func declarePackageManager(fsys fs.FS, lockPath string, lf pnpmLockfile, pkgs []*extractor.Package, keys []string) error {
	roots := map[string]string{}
	for name, dep := range lf.Importers["."].PackageManagerDependencies {
		if key, ok := pnpmDependencyKey(name, dep.Version, lf.Version); ok {
			roots[key] = name
		}
	}
	if len(roots) == 0 || fsys == nil {
		return nil
	}
	manifest := path.Join(path.Dir(lockPath), "package.json")
	data, err := fs.ReadFile(fsys, manifest)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	// The packagejson extractor reports a package.json that does not parse.
	var pj map[string]any
	if err := json.Unmarshal(data, &pj); err != nil {
		log.Warnf("pnpmlock: %s does not parse, so the pnpm packages keep the lockfile as their fix site: %v", manifest, err)
		return nil
	}
	value, _ := pj[packageManagerField].(string)
	for key, name := range roots {
		if !strings.HasPrefix(value, name+"@") {
			continue
		}
		decl := &model.Declaration{Path: manifest, Line: fieldLine(data), Field: packageManagerField, Package: name}
		installed := installedBy(lf, key)
		for i, p := range pkgs {
			if m, ok := p.Metadata.(*lockmeta.Metadata); ok && installed[keys[i]] {
				m.DeclaredAt = decl
			}
		}
	}
	return nil
}

// fieldLine is the line of the packageManager field, or 0.
func fieldLine(data []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		if packageManagerLine.Match(sc.Bytes()) {
			return n
		}
	}
	return 0
}

// installedBy returns the keys of root and of each package that root
// requires, through the snapshots of lockfile v9.
func installedBy(lf pnpmLockfile, root string) map[string]bool {
	children := map[string][]string{}
	for p, snap := range lf.Snapshots {
		name, version, err := extractPnpmPackageNameAndVersion(p, lf.Version)
		if err != nil || name == "" || version == "" {
			continue
		}
		parent := name + "@" + trimPeers(version)
		for _, group := range []map[string]string{snap.Dependencies, snap.OptionalDependencies} {
			for child, ref := range group {
				if key, ok := pnpmDependencyKey(child, ref, lf.Version); ok {
					children[parent] = append(children[parent], key)
				}
			}
		}
	}
	seen := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		for _, c := range children[k] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return seen
}

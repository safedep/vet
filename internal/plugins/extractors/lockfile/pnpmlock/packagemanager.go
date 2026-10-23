package pnpmlock

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
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

var errNotObject = errors.New("the document is not a JSON object")

// maxPackageJSON bounds the read of package.json. A package.json of a
// project is a few kilobytes.
const maxPackageJSON = 1 << 20

// declarePackageManager marks each package that the lockfile document
// installs for the package manager with the "packageManager" field of the
// package.json next to the lockfile. A fix of such a package edits that
// field, not the lockfile. Only a document that installs the package
// manager and no project dependency marks packages, so a crafted lockfile
// cannot move the fix of a project package to package.json.
func declarePackageManager(fsys fs.FS, lockPath string, lf pnpmLockfile, pkgs []*extractor.Package, keys []string) error {
	roots := map[string]string{}
	for name, dep := range lf.Importers["."].PackageManagerDependencies {
		if key, ok := pnpmDependencyKey(name, dep.Version, lf.Version); ok {
			roots[key] = name
		}
	}
	if len(roots) == 0 || fsys == nil || installsProject(lf) {
		return nil
	}
	manifest := path.Join(path.Dir(lockPath), "package.json")
	value, line, err := readPackageManager(fsys, manifest)
	if err != nil || value == "" {
		return err
	}
	for key, name := range roots {
		if !strings.HasPrefix(value, name+"@") {
			continue
		}
		decl := &model.Declaration{Path: manifest, Line: line, Field: packageManagerField, Package: name}
		installed := installedBy(lf, key)
		for i, p := range pkgs {
			if m, ok := p.Metadata.(*lockmeta.Metadata); ok && installed[keys[i]] {
				m.DeclaredAt = decl
			}
		}
	}
	return nil
}

// installsProject reports a lockfile document that installs a dependency
// of a project.
func installsProject(lf pnpmLockfile) bool {
	for _, imp := range append(slices.Collect(maps.Values(lf.Importers)), lf.Root) {
		if len(imp.Dependencies)+len(imp.DevDependencies)+len(imp.OptionalDependencies) > 0 {
			return true
		}
	}
	return false
}

// readPackageManager returns the packageManager field of package.json and
// its line, or "" when the file or the field does not exist. It reads at
// most maxPackageJSON bytes, as the walk of the scan reads files. On a
// directory it reads only a regular file, not a link. The FS of an image
// has no Lstat, so it follows a link, but only to a file in the image.
func readPackageManager(fsys fs.FS, name string) (value string, line int, err error) {
	info, err := fs.Lstat(fsys, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", 0, nil
	case err != nil:
		return "", 0, err
	case !info.Mode().IsRegular() || info.Size() > maxPackageJSON:
		return "", 0, nil
	}
	f, err := fsys.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	data, err := io.ReadAll(io.LimitReader(f, maxPackageJSON))
	if err != nil {
		return "", 0, err
	}
	// The packagejson extractor reports a package.json that does not parse.
	value, line, perr := packageManager(data)
	if perr != nil {
		log.Warnf("pnpmlock: %s does not parse, so a fix of pnpm names the lockfile: %v", name, perr)
		return "", 0, nil
	}
	return value, line, nil
}

// packageManager returns the top-level packageManager field of a
// package.json and its line. A nested key of the same name, as in
// devEngines, is not the field. The last field wins, as in json.Unmarshal.
func packageManager(data []byte) (value string, line int, err error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", 0, cmp.Or(err, errNotObject)
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return "", 0, err
		}
		at := dec.InputOffset()
		var v any
		if err := dec.Decode(&v); err != nil {
			return "", 0, err
		}
		if key == packageManagerField {
			value, _ = v.(string)
			line = bytes.Count(data[:at], []byte("\n")) + 1
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", 0, err
	}
	return value, line, nil
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

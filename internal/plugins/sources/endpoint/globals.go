package endpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/model"
)

// userGlobalRoots lists the npm global package directories of one user:
// a custom npm prefix, nvm, and the Windows npm prefix.
func userGlobalRoots(home string) []string {
	roots := []string{
		filepath.Join(home, ".npm-global", "lib", "node_modules"),
		filepath.Join(home, "AppData", "Roaming", "npm", "node_modules"),
	}
	nvm, err := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "lib", "node_modules"))
	if err != nil {
		log.Debugf("endpoint: list nvm versions: %v", err)
	}
	return append(roots, nvm...)
}

// systemGlobalRoots lists the machine-wide npm global package directories.
// vet reads them with --all-users only.
func systemGlobalRoots() []string {
	if runtime.GOOS == "windows" {
		return []string{filepath.Join(os.Getenv("ProgramFiles"), "nodejs", "node_modules")}
	}
	return []string{"/usr/local/lib/node_modules", "/usr/lib/node_modules", "/opt/homebrew/lib/node_modules"}
}

// globalPackages returns one manifest for each global package directory
// that exists. Each package is a direct npm package.
func globalPackages(roots []string) []*model.Manifest {
	var out []*model.Manifest
	for _, root := range roots {
		pkgs := installedPackages(root)
		if len(pkgs) == 0 {
			continue
		}
		out = append(out, &model.Manifest{
			ID: model.ManifestID(root, "endpoint/npm-global"), Path: root, Ecosystem: model.EcosystemNpm,
			Kind: model.ManifestKindEndpoint, Extractor: "endpoint/npm-global", Packages: pkgs,
		})
	}
	return out
}

func installedPackages(root string) []*model.Package {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, "."):
		case strings.HasPrefix(name, "@"):
			scoped, err := os.ReadDir(filepath.Join(root, name))
			if err != nil {
				continue
			}
			for _, s := range scoped {
				dirs = append(dirs, filepath.Join(root, name, s.Name()))
			}
		default:
			dirs = append(dirs, filepath.Join(root, name))
		}
	}
	sort.Strings(dirs)
	var out []*model.Package
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, "package.json"))
		if err != nil {
			continue
		}
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(b, &pj); err != nil || pj.Name == "" || pj.Version == "" {
			log.Debugf("endpoint: skip %s: no name or version", d)
			continue
		}
		id, err := model.NewPackageVersion(model.EcosystemNpm, pj.Name, pj.Version)
		if err != nil {
			log.Debugf("endpoint: skip %s: %v", d, err)
			continue
		}
		out = append(out, &model.Package{ID: id, Direct: true})
	}
	return out
}

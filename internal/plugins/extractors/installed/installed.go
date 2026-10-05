// Package installed holds the extractors of installed packages: the Scalibr
// artifact extractors, with the vet rules for npm and for Go binaries.
package installed

import (
	"context"
	"path"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/inventory"
)

// NodeModulesName is the name of the npm extractor. Scalibr and vet both use
// the name javascript/packagejson for the extractors that read a project
// package.json, so the installed reader has its own name.
const NodeModulesName = "javascript/nodemodules"

// installDirs are the directories that hold installed packages. A declared
// extractor does not read a file under them.
var installDirs = map[string]bool{"node_modules": true, "site-packages": true, "dist-packages": true}

// InInstallDir reports whether a path, with "/", is under a directory that
// holds installed packages.
func InInstallDir(p string) bool {
	for part := range strings.SplitSeq(path.Dir(p), "/") {
		if installDirs[part] {
			return true
		}
	}
	return false
}

// Extractors returns the extractors of installed packages.
func Extractors() ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{}
	nm, err := packagejson.New(cfg)
	if err != nil {
		return nil, err
	}
	gb, err := gobinary.New(cfg)
	if err != nil {
		return nil, err
	}
	out := []filesystem.Extractor{nodeModules{nm}, goBinary{gb}}
	for _, newFn := range []func(*cpb.PluginConfig) (filesystem.Extractor, error){wheelegg.New, gem.New, cargoauditable.New} {
		e, err := newFn(cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// nodeModules reads the package.json of a package directory directly under
// node_modules. Scalibr reads each package.json with a name and a version,
// so it also reports the project and the test fixtures inside a package.
type nodeModules struct{ filesystem.Extractor }

func (nodeModules) Name() string { return NodeModulesName }

func (n nodeModules) FileRequired(api filesystem.FileAPI) bool {
	return packageRoot(api.Path()) && n.Extractor.FileRequired(api)
}

// packageRoot reports node_modules/NAME/package.json or
// node_modules/@SCOPE/NAME/package.json, at any depth.
func packageRoot(p string) bool {
	if path.Base(p) != "package.json" {
		return false
	}
	dir := path.Dir(p)
	parent := path.Dir(dir)
	if strings.HasPrefix(path.Base(parent), "@") {
		parent = path.Dir(parent)
	}
	return path.Base(parent) == "node_modules"
}

// goBinary names the Go toolchain of a binary stdlib, as the go.mod
// extractor does. Scalibr names it go. A main module with no release
// version is a local build of the project, not a module to look up.
type goBinary struct{ filesystem.Extractor }

func (g goBinary) Extract(ctx context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := g.Extractor.Extract(ctx, in)
	pkgs := inv.Packages[:0]
	for _, p := range inv.Packages {
		if p.Version == "" || p.Version == "(devel)" {
			continue
		}
		if p.Name == "go" {
			p.Name = "stdlib"
		}
		pkgs = append(pkgs, p)
	}
	inv.Packages = pkgs
	return inv, err
}

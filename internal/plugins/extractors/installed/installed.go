// Package installed holds the extractors of installed packages: the Scalibr
// artifact extractors, with the vet rules for npm and for Go binaries.
package installed

import (
	"context"
	"debug/buildinfo"
	"io"
	"path"
	"runtime/debug"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/inventory"
	"github.com/rust-secure-code/go-rustaudit"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// NodeModulesName is the name of the npm extractor. Scalibr and vet both use
// the name javascript/packagejson for the extractors that read a project
// package.json, so the installed reader has its own name.
const NodeModulesName = "javascript/nodemodules"

// installDirs are the directories that hold installed packages. A declared
// extractor does not read a file under them.
var installDirs = map[string]bool{"node_modules": true, "site-packages": true, "dist-packages": true}

// IsInstallDir reports a directory name that holds installed packages.
func IsInstallDir(name string) bool { return installDirs[name] }

// InInstallDir reports whether a path, with "/", is under a directory that
// holds installed packages.
func InInstallDir(p string) bool {
	for part := range strings.SplitSeq(path.Dir(p), "/") {
		if IsInstallDir(part) {
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
	we, err := wheelegg.New(cfg)
	if err != nil {
		return nil, err
	}
	ge, err := gem.New(cfg)
	if err != nil {
		return nil, err
	}
	ca, err := cargoauditable.New(cfg)
	if err != nil {
		return nil, err
	}
	return []filesystem.Extractor{nodeModules{nm}, goBinary{gb}, pythonDist{we}, ge, rustBinary{ca}}, nil
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

// pythonDist reads the metadata of a distribution in site-packages or
// dist-packages. The egg-info of an editable install and a wheel in dist/
// describe the project itself.
type pythonDist struct{ filesystem.Extractor }

func (p pythonDist) FileRequired(api filesystem.FileAPI) bool {
	return InInstallDir(api.Path()) && p.Extractor.FileRequired(api)
}

// goBinary names the Go toolchain of a binary stdlib, as the go.mod
// extractor does. Scalibr names it go. A main module with no release
// version, such as (devel) or the pseudo-version of a build in a git
// checkout, is the project itself, not a module to look up.
type goBinary struct{ filesystem.Extractor }

func (g goBinary) Extract(ctx context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := g.Extractor.Extract(ctx, in)
	var main debug.Module
	if ra, ok := in.Reader.(io.ReaderAt); ok {
		if bi, err := buildinfo.Read(ra); err == nil {
			main = bi.Main
		}
	}
	pkgs := inv.Packages[:0]
	for _, p := range inv.Packages {
		if p.Name == main.Path && !released(main.Version) {
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

// released reports a module version that a release tagged.
func released(v string) bool {
	return semver.IsValid(v) && !module.IsPseudoVersion(v) && !strings.Contains(v, "+dirty")
}

// rustBinary drops the root crate of a binary. cargo-auditable records the
// crate that the binary builds as a dependency, and a local build gives it
// the version of the project.
type rustBinary struct{ filesystem.Extractor }

func (r rustBinary) Extract(ctx context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := r.Extractor.Extract(ctx, in)
	ra, ok := in.Reader.(io.ReaderAt)
	if err != nil || !ok {
		return inv, err
	}
	info, aerr := rustaudit.GetDependencyInfo(ra)
	if aerr != nil {
		return inv, nil
	}
	roots := map[string]bool{}
	for _, d := range info.Packages {
		if d.Root {
			roots[d.Name+"@"+d.Version] = true
		}
	}
	pkgs := inv.Packages[:0]
	for _, p := range inv.Packages {
		if !roots[p.Name+"@"+p.Version] {
			pkgs = append(pkgs, p)
		}
	}
	inv.Packages = pkgs
	return inv, nil
}

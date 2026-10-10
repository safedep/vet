// Package extractors composes the extractor set of a scan. The declared set
// is the Scalibr source extractors, with the vet lockfile copies in place of
// the upstream extractors of the same name, the vet copy of the GitHub
// Actions extractor, the go.mod extractor with the stdlib rule, and the vet
// extractors for Terraform and for the manifests package.json, Cargo.toml
// and pyproject.toml. The installed set reads the packages on disk.
package extractors

import (
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/safedep/vet/v2/internal/plugins/extractors/agentconfig"
	"github.com/safedep/vet/v2/internal/plugins/extractors/cargotoml"
	"github.com/safedep/vet/v2/internal/plugins/extractors/githubactions"
	"github.com/safedep/vet/v2/internal/plugins/extractors/gomod"
	"github.com/safedep/vet/v2/internal/plugins/extractors/hiddencode"
	"github.com/safedep/vet/v2/internal/plugins/extractors/installed"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile"
	"github.com/safedep/vet/v2/internal/plugins/extractors/packagejson"
	"github.com/safedep/vet/v2/internal/plugins/extractors/pyproject"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/plugins/extractors/terraform"
	"github.com/safedep/vet/v2/model"
)

// For returns the extractors that read the packages that p selects. The
// workflow, agent config and hidden-code extractors run for every
// selection, because their controls read the files, not the packages.
func For(p model.Packages) ([]filesystem.Extractor, error) {
	if !slices.Contains(model.PackagesValues, p) {
		return nil, fmt.Errorf("extractors: unknown package selection %q", p)
	}
	d, err := Default()
	if err != nil {
		return nil, err
	}
	var out []filesystem.Extractor
	for _, e := range d {
		if p.Declared() || scalibr.ReadsFileOnly(e) {
			out = append(out, declared{e})
		}
	}
	if p.Installed() {
		in, err := installed.Extractors()
		if err != nil {
			return nil, err
		}
		out = append(out, in...)
	}
	return out, nil
}

// Default returns the extractors of a code scan, sorted by name.
func Default() ([]filesystem.Extractor, error) {
	base, err := scalibr.SourceExtractors()
	if err != nil {
		return nil, err
	}
	vet, err := lockfile.Extractors()
	if err != nil {
		return nil, err
	}
	gha, err := githubactions.New(nil)
	if err != nil {
		return nil, err
	}
	gm, err := gomod.New()
	if err != nil {
		return nil, err
	}
	vet = append(vet, gha, gm, terraform.New(), packagejson.New(), cargotoml.New(), pyproject.New(), agentconfig.New(), hiddencode.New())
	return Override(base, vet...), nil
}

// declared is an extractor of the declared set. A file under node_modules
// or a Python install directory belongs to an installed package, not to
// the project, so a declared extractor does not read it.
type declared struct{ filesystem.Extractor }

func (d declared) FileRequired(api filesystem.FileAPI) bool {
	return !installed.InInstallDir(api.Path()) && d.Extractor.FileRequired(api)
}

// Override replaces each extractor of base that has the name of an
// extractor in with, and adds the others.
func Override(base []filesystem.Extractor, with ...filesystem.Extractor) []filesystem.Extractor {
	byName := map[string]filesystem.Extractor{}
	for _, e := range with {
		byName[e.Name()] = e
	}
	out := make([]filesystem.Extractor, 0, len(base)+len(with))
	for _, e := range base {
		if r, ok := byName[e.Name()]; ok {
			out = append(out, r)
			delete(byName, e.Name())
			continue
		}
		out = append(out, e)
	}
	for _, e := range with {
		if _, left := byName[e.Name()]; left {
			out = append(out, e)
		}
	}
	return out
}

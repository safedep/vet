// Package extractors composes the extractor set of a code scan: the
// Scalibr source extractors, with the vet lockfile copies in place of the
// upstream extractors of the same name, the vet copy of the GitHub Actions
// extractor, and the vet extractors for Terraform and package.json.
package extractors

import (
	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/safedep/vet/v2/internal/plugins/extractors/githubactions"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile"
	"github.com/safedep/vet/v2/internal/plugins/extractors/packagejson"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/plugins/extractors/terraform"
)

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
	vet = append(vet, gha, terraform.New(), packagejson.New())
	return Override(base, vet...), nil
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

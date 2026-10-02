// Package scalibr is the adapter from OSV-Scalibr to the vet model. It is
// the only vet package that reads Scalibr inventory types. It picks the
// Scalibr extractors that vet runs, and it converts their output to
// model.Manifest.
package scalibr

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denojson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denotssource"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/githubactions"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config"
)

// sourceGroups are the Scalibr extractor groups for code: lockfiles and
// manifests, Java archives, SBOMs and GitHub Actions workflows. vet does
// not run the secret, OS, container or tool-version extractors on code.
var sourceGroups = []list.InitMap{
	list.CppSource, list.JavaSource, list.JavaArtifact, list.JavascriptSource, list.PythonSource,
	list.GoSource, list.DartSource, list.ErlangSource, list.ElixirSource, list.GleamSource,
	list.HaskellSource, list.PHPSource, list.RSource, list.RubySource, list.RustSource,
	list.JuliaSource, list.DotnetSource, list.SwiftSource, list.NimSource, list.OcamlSource,
	list.LuaSource, list.CPANSource, list.SBOM,
	{githubactions.Name: list.MiscSource[githubactions.Name]},
}

// excluded are Scalibr extractors that do not read the dependencies of a
// project. Scalibr's packagejson reads the package that a package.json
// describes. vet reads the dependencies of package.json with its own
// extractor (decisions P8).
var excluded = map[string]bool{
	packagejson.Name:  true,
	denojson.Name:     true,
	denotssource.Name: true,
}

// SourceExtractors returns the Scalibr extractors that vet runs on code,
// sorted by name. It leaves out each extractor that needs the network,
// because a scan reads the network only through its enrichers.
func SourceExtractors() ([]filesystem.Extractor, error) {
	inits := list.InitMap{}
	for _, g := range sourceGroups {
		maps.Copy(inits, g)
	}
	cfg := config.DefaultPluginConfig()
	var out []filesystem.Extractor
	for _, name := range slices.Sorted(maps.Keys(inits)) {
		if excluded[name] {
			continue
		}
		for _, initFn := range inits[name] {
			e, err := initFn(cfg)
			if err != nil {
				return nil, fmt.Errorf("scalibr: create extractor %s: %w", name, err)
			}
			if e.Requirements().Network == plugin.NetworkOnline {
				continue
			}
			out = append(out, e)
		}
	}
	return out, nil
}

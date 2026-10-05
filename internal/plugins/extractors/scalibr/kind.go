package scalibr

import (
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"

	"github.com/safedep/vet/v2/internal/plugins/extractors/installed"
	"github.com/safedep/vet/v2/model"
)

// lockfiles are the extractors that read a resolved dependency set. Every
// other extractor reads a manifest of declared dependencies. The vet copies
// of the graph-aware extractors keep the Scalibr names.
var lockfiles = map[string]bool{
	"javascript/packagelockjson": true,
	"javascript/pnpmlock":        true,
	"javascript/yarnlock":        true,
	"javascript/bunlock":         true,
	"python/uvlock":              true,
	"python/poetrylock":          true,
	"python/pipfilelock":         true,
	"python/pdmlock":             true,
	"python/pylock":              true,
	"rust/cargolock":             true,
	"ruby/gemfilelock":           true,
	"php/composerlock":           true,
	"java/gradlelockfile":        true,
	"cpp/conanlock":              true,
	"elixir/mixlock":             true,
	"dart/pubspec":               true,
	"r/renvlock":                 true,
	"haskell/stacklock":          true,
	"dotnet/packageslockjson":    true,
	"dotnet/paketlock":           true,
	"swift/podfilelock":          true,
	"swift/packageresolved":      true,
	"go/gomod":                   true,
}

// installedReaders are the extractors that read a package on disk.
var installedReaders = map[string]bool{
	installed.NodeModulesName: true,
	wheelegg.Name:             true,
	gobinary.Name:             true,
	gem.Name:                  true,
	cargoauditable.Name:       true,
}

// ReadsInstalled reports an extractor that reads a package on disk.
func ReadsInstalled(e filesystem.Extractor) bool { return installedReaders[e.Name()] }

// ReadsFileOnly reports an extractor whose controls read the file itself:
// a workflow or an agent config file. Its manifest is not a package source.
func ReadsFileOnly(e filesystem.Extractor) bool {
	k := kindOf(e.Name())
	return k == model.ManifestKindWorkflow || k == model.ManifestKindAgentConfig
}

// kindOf returns the manifest kind of an extractor.
func kindOf(extractor string) model.ManifestKind {
	switch {
	case installedReaders[extractor]:
		return model.ManifestKindInstalled
	case lockfiles[extractor]:
		return model.ManifestKindLockfile
	case strings.HasPrefix(extractor, "sbom/"):
		return model.ManifestKindSBOM
	case extractor == "github/actions":
		return model.ManifestKindWorkflow
	case extractor == "agent/config":
		return model.ManifestKindAgentConfig
	}
	return model.ManifestKindManifest
}

package scalibr

import (
	"strings"

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

// kindOf returns the manifest kind of an extractor.
func kindOf(extractor string) model.ManifestKind {
	switch {
	case lockfiles[extractor]:
		return model.ManifestKindLockfile
	case strings.HasPrefix(extractor, "sbom/"):
		return model.ManifestKindSBOM
	case extractor == "github/actions":
		return model.ManifestKindWorkflow
	}
	return model.ManifestKindManifest
}

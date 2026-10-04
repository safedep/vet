package codeusage

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/model"
)

// module is one module that the code imports, with the language of the file
// and the package hint of the analysis.
type module struct {
	Language string
	Hint     string
	Name     string
}

// ecosystemLanguages are the languages whose imports a package of an
// ecosystem can provide. Evidence with no language matches every ecosystem.
var ecosystemLanguages = map[model.Ecosystem][]string{
	model.EcosystemNpm:       {"javascript", "typescript"},
	model.EcosystemPyPI:      {"python"},
	model.EcosystemMaven:     {"java", "kotlin"},
	model.EcosystemGo:        {"go"},
	model.EcosystemCargo:     {"rust"},
	model.EcosystemRubyGems:  {"ruby"},
	model.EcosystemNuGet:     {"csharp"},
	model.EcosystemPackagist: {"php"},
}

// provider tells whether a package provides an imported module. Each
// ecosystem has its own rule, because a registry name relates to an import
// name in its own way.
type provider struct {
	// autoload maps a PHP namespace prefix, with a trailing "\", to the
	// Composer package that autoloads it.
	autoload map[string]string
}

func (pv provider) provides(id model.PackageVersion, m module) bool {
	if m.Language != "" && !slices.Contains(ecosystemLanguages[id.Ecosystem()], m.Language) {
		return false
	}

	name := normalize(id.RawName())
	hint, mod := normalize(m.Hint), normalize(m.Name)
	if name == hint || name == normalize(rootModule(m.Name)) {
		return true
	}

	switch id.Ecosystem() {
	case model.EcosystemPyPI:
		// A namespace package installs a dotted module, as
		// google-cloud-storage installs google.cloud.storage.
		return pep503(name) == pep503(hint) || slices.ContainsFunc(dottedPrefixes(mod, "-"), func(prefix string) bool {
			return pep503(prefix) == pep503(name)
		})
	case model.EcosystemMaven:
		group, _, _ := strings.Cut(name, ":")
		return mod == group || strings.HasPrefix(mod, group+".")
	case model.EcosystemNuGet:
		// Microsoft.Extensions.Logging comes from the package of that name
		// or from Microsoft.Extensions.Logging.Abstractions. A namespace of
		// one segment, such as System, is too wide for the second rule.
		return mod == name || strings.HasPrefix(mod, name+".") ||
			(strings.Count(mod, ".") > 0 && strings.HasPrefix(name, mod+"."))
	case model.EcosystemCargo:
		return strings.ReplaceAll(name, "-", "_") == strings.ReplaceAll(hint, "-", "_")
	case model.EcosystemRubyGems:
		// require 'rspec/core' loads the rspec-core gem.
		return slices.Contains(dottedPrefixes(strings.ReplaceAll(mod, "/", "."), "-"), name)
	case model.EcosystemGo:
		return strings.HasPrefix(mod, name+"/")
	case model.EcosystemPackagist:
		return pv.autoloadPackage(m.Name) == name
	}
	return false
}

// autoloadPackage returns the Composer package whose PSR-4 prefix is the
// longest prefix of a PHP class name.
func (pv provider) autoloadPackage(class string) string {
	best, pkg := 0, ""
	for prefix, name := range pv.autoload {
		if len(prefix) > best && strings.HasPrefix(strings.TrimPrefix(class, `\`)+`\`, prefix) {
			best, pkg = len(prefix), name
		}
	}
	return pkg
}

// dottedPrefixes returns each prefix of a dotted name, with its dots
// replaced by sep: a.b.c gives a, a-b and a-b-c for "-".
func dottedPrefixes(name, sep string) []string {
	parts := strings.Split(name, ".")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, strings.Join(parts[:i+1], sep))
	}
	return out
}

// pep503 normalizes a Python distribution name.
func pep503(name string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(name)
}

// composerLock is the part of composer.lock that tells which package
// autoloads which namespace.
type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name     string `json:"name"`
	Autoload struct {
		PSR4 map[string]json.RawMessage `json:"psr-4"`
		PSR0 map[string]json.RawMessage `json:"psr-0"`
	} `json:"autoload"`
}

// readAutoload reads the namespace prefixes of the composer.lock files
// under dir. A file that vet cannot read or parse adds nothing, and vet
// logs it.
func readAutoload(dir string) (map[string]string, error) {
	out := map[string]string{}
	err := readManifests(dir, func(name string) bool { return name == "composer.lock" }, func(path string, data []byte) {
		var lock composerLock
		if err := json.Unmarshal(data, &lock); err != nil {
			log.Warnf("codeusage: cannot parse %s: %v", path, err)
			return
		}
		for _, p := range append(lock.Packages, lock.PackagesDev...) {
			for prefix := range p.Autoload.PSR4 {
				out[prefix] = normalize(p.Name)
			}
			for prefix := range p.Autoload.PSR0 {
				out[strings.TrimSuffix(prefix, `\`)+`\`] = normalize(p.Name)
			}
		}
	})
	return out, err
}

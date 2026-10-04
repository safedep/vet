package model

import (
	"fmt"
	"sort"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
)

// Ecosystem is the name of a package ecosystem, as a person reads and writes
// it in a flag, a config file, a report or a policy. The names come from
// dry/api/pb, so every SafeDep tool prints the same name for one ecosystem.
type Ecosystem string

const (
	EcosystemNpm               Ecosystem = "npm"
	EcosystemPyPI              Ecosystem = "pypi"
	EcosystemMaven             Ecosystem = "maven"
	EcosystemGo                Ecosystem = "go"
	EcosystemCargo             Ecosystem = "cargo"
	EcosystemRubyGems          Ecosystem = "rubygems"
	EcosystemNuGet             Ecosystem = "nuget"
	EcosystemPackagist         Ecosystem = "packagist"
	EcosystemPub               Ecosystem = "pub"
	EcosystemGitHubActions     Ecosystem = "github-actions"
	EcosystemTerraformProvider Ecosystem = "terraform-provider"
	EcosystemVSCode            Ecosystem = "vscode"
	EcosystemOpenVSX           Ecosystem = "openvsx"
)

// ecosystems maps each ecosystem that vet reads to its SafeDep API value.
// TestEcosystemsMatchDry checks each name against the dry name table.
var ecosystems = map[Ecosystem]packagev1.Ecosystem{
	EcosystemNpm:               packagev1.Ecosystem_ECOSYSTEM_NPM,
	EcosystemPyPI:              packagev1.Ecosystem_ECOSYSTEM_PYPI,
	EcosystemMaven:             packagev1.Ecosystem_ECOSYSTEM_MAVEN,
	EcosystemGo:                packagev1.Ecosystem_ECOSYSTEM_GO,
	EcosystemCargo:             packagev1.Ecosystem_ECOSYSTEM_CARGO,
	EcosystemRubyGems:          packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS,
	EcosystemNuGet:             packagev1.Ecosystem_ECOSYSTEM_NUGET,
	EcosystemPackagist:         packagev1.Ecosystem_ECOSYSTEM_PACKAGIST,
	EcosystemPub:               packagev1.Ecosystem_ECOSYSTEM_PUB,
	EcosystemGitHubActions:     packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS,
	EcosystemTerraformProvider: packagev1.Ecosystem_ECOSYSTEM_TERRAFORM_PROVIDER,
	EcosystemVSCode:            packagev1.Ecosystem_ECOSYSTEM_VSCODE,
	EcosystemOpenVSX:           packagev1.Ecosystem_ECOSYSTEM_OPENVSX,
}

// Ecosystems returns every ecosystem that vet reads, sorted.
func Ecosystems() []Ecosystem {
	out := make([]Ecosystem, 0, len(ecosystems))
	for e := range ecosystems {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Valid reports whether vet reads the ecosystem.
func (e Ecosystem) Valid() bool {
	_, ok := ecosystems[e]
	return ok
}

// ecosystemOf returns the ecosystem of a SafeDep API value, or an error for
// a value that vet does not read.
func ecosystemOf(value packagev1.Ecosystem) (Ecosystem, error) {
	name, err := pb.EcosystemName(value)
	if err != nil {
		return "", err
	}
	if e := Ecosystem(name); e.Valid() {
		return e, nil
	}
	return "", fmt.Errorf("vet does not read the %s ecosystem", name)
}

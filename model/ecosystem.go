package model

import (
	"fmt"
	"sort"
)

// Ecosystem is a closed set of package ecosystems.
type Ecosystem string

const (
	EcosystemNpm           Ecosystem = "npm"
	EcosystemPyPI          Ecosystem = "pypi"
	EcosystemMaven         Ecosystem = "maven"
	EcosystemGo            Ecosystem = "go"
	EcosystemCargo         Ecosystem = "cargo"
	EcosystemRubyGems      Ecosystem = "rubygems"
	EcosystemNuGet         Ecosystem = "nuget"
	EcosystemPackagist     Ecosystem = "packagist"
	EcosystemPub           Ecosystem = "pub"
	EcosystemGitHubActions Ecosystem = "github-actions"
	EcosystemTerraform     Ecosystem = "terraform"
	EcosystemVSCode        Ecosystem = "vscode"
	EcosystemOpenVSX       Ecosystem = "openvsx"
)

// EcosystemInfo is one row of the ecosystem table.
type EcosystemInfo struct {
	Ecosystem Ecosystem
	PURLType  string
	OSVName   string
}

// ecosystems is the one ecosystem table. Every lookup goes through it.
var ecosystems = []EcosystemInfo{
	{EcosystemNpm, "npm", "npm"},
	{EcosystemPyPI, "pypi", "PyPI"},
	{EcosystemMaven, "maven", "Maven"},
	{EcosystemGo, "golang", "Go"},
	{EcosystemCargo, "cargo", "crates.io"},
	{EcosystemRubyGems, "gem", "RubyGems"},
	{EcosystemNuGet, "nuget", "NuGet"},
	{EcosystemPackagist, "composer", "Packagist"},
	{EcosystemPub, "pub", "Pub"},
	{EcosystemGitHubActions, "githubactions", "GitHub Actions"},
	{EcosystemTerraform, "terraform", ""},
	{EcosystemVSCode, "vscode", ""},
	{EcosystemOpenVSX, "openvsx", ""},
}

var (
	byEcosystem = map[Ecosystem]EcosystemInfo{}
	byPURLType  = map[string]EcosystemInfo{}
)

func init() {
	for _, e := range ecosystems {
		byEcosystem[e.Ecosystem] = e
		byPURLType[e.PURLType] = e
	}
	// "github" is the PURL type that some tools use for GitHub Actions.
	byPURLType["github"] = byEcosystem[EcosystemGitHubActions]
}

// Ecosystems returns every known ecosystem, sorted.
func Ecosystems() []Ecosystem {
	out := make([]Ecosystem, 0, len(ecosystems))
	for _, e := range ecosystems {
		out = append(out, e.Ecosystem)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Info returns the table row of the ecosystem.
func (e Ecosystem) Info() (EcosystemInfo, error) {
	info, ok := byEcosystem[e]
	if !ok {
		return EcosystemInfo{}, fmt.Errorf("unknown ecosystem %q", string(e))
	}
	return info, nil
}

// Valid reports whether the ecosystem is in the table.
func (e Ecosystem) Valid() bool {
	_, ok := byEcosystem[e]
	return ok
}

// EcosystemFromPURLType returns the ecosystem of a PURL type.
func EcosystemFromPURLType(t string) (Ecosystem, error) {
	info, ok := byPURLType[t]
	if !ok {
		return "", fmt.Errorf("unknown PURL type %q", t)
	}
	return info.Ecosystem, nil
}

// EcosystemFromOSV returns the ecosystem of an OSV ecosystem name.
func EcosystemFromOSV(name string) (Ecosystem, error) {
	for _, e := range ecosystems {
		if e.OSVName != "" && e.OSVName == name {
			return e.Ecosystem, nil
		}
	}
	return "", fmt.Errorf("unknown OSV ecosystem %q", name)
}

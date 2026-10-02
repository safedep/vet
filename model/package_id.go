package model

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// PackageID is the identity of one package version. It comes from the PURL.
type PackageID struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	Version   string    `json:"version,omitempty"`
	// Subpath is the PURL subpath, for example "init" for the GitHub
	// action github/codeql-action/init.
	Subpath string `json:"subpath,omitempty"`
}

// ParsePURL parses a package URL into a PackageID.
func ParsePURL(s string) (PackageID, error) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return PackageID{}, fmt.Errorf("parse PURL %q: %w", s, err)
	}

	eco, err := EcosystemFromPURLType(p.Type)
	if err != nil {
		return PackageID{}, err
	}

	id := PackageID{Ecosystem: eco, Namespace: p.Namespace, Name: p.Name, Version: p.Version, Subpath: p.Subpath}
	return id, id.Validate()
}

// Validate checks that the identity has an ecosystem and a name.
func (id PackageID) Validate() error {
	if !id.Ecosystem.Valid() {
		return fmt.Errorf("unknown ecosystem %q", string(id.Ecosystem))
	}
	if id.Name == "" {
		return fmt.Errorf("package name is empty")
	}
	return nil
}

// PURL returns the package URL of the identity.
func (id PackageID) PURL() string {
	info, err := id.Ecosystem.Info()
	if err != nil {
		return ""
	}
	return packageurl.NewPackageURL(info.PURLType, id.Namespace, id.Name, id.Version, nil, id.Subpath).ToString()
}

// QualifiedName returns the name that the ecosystem's users write, for
// example "@scope/name" for npm or "group:artifact" for Maven.
func (id PackageID) QualifiedName() string {
	name := id.Name
	switch {
	case id.Namespace == "":
	case id.Ecosystem == EcosystemMaven:
		name = id.Namespace + ":" + id.Name
	default:
		name = id.Namespace + "/" + id.Name
	}
	if id.Subpath != "" {
		name += "/" + id.Subpath
	}
	return name
}

// String returns "<ecosystem>/<qualified name>@<version>".
func (id PackageID) String() string {
	var b strings.Builder
	b.WriteString(string(id.Ecosystem))
	b.WriteString("/")
	b.WriteString(id.QualifiedName())
	if id.Version != "" {
		b.WriteString("@")
		b.WriteString(id.Version)
	}
	return b.String()
}

// Package returns the identity of the package that holds a subpath: the
// identity with no subpath.
func (id PackageID) Package() PackageID {
	id.Subpath = ""
	return id
}

// WithoutVersion returns the identity with no version.
func (id PackageID) WithoutVersion() PackageID {
	id.Version = ""
	return id
}

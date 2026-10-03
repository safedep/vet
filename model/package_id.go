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
	return fromPURL(p)
}

// NewPackageID builds a PackageID from the parts of a PURL, with the same
// normal form as ParsePURL. It does not encode and parse a PURL string, so
// it is fast. A name with a "/" goes through ParsePURL, which moves the
// leading part into the namespace.
func NewPackageID(purlType, namespace, name, version, subpath string) (PackageID, error) {
	p := packageurl.PackageURL{Type: purlType, Namespace: namespace, Name: name, Version: version, Subpath: subpath}
	if strings.Contains(name, "/") {
		return ParsePURL(p.ToString())
	}
	if err := p.Normalize(); err != nil {
		return PackageID{}, fmt.Errorf("parse PURL %q: %w", p.ToString(), err)
	}
	return fromPURL(p)
}

func fromPURL(p packageurl.PackageURL) (PackageID, error) {
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
	if plainPURL(id) {
		return plainPURLString(info.PURLType, id)
	}
	return packageurl.NewPackageURL(info.PURLType, id.Namespace, id.Name, id.Version, nil, id.Subpath).ToString()
}

// plainPURL reports an identity with no character that a PURL encodes.
// Its PURL is a plain join of the parts. A scan builds a PURL for each
// package many times, and the encoder is slow.
func plainPURL(id PackageID) bool {
	return plain(id.Namespace, true) && plain(id.Name, false) && plain(id.Version, false) && plain(id.Subpath, true)
}

// plain reports a part that packageurl-go writes as it is. "/" splits the
// namespace and the subpath into segments, and a name or a version
// encodes it.
func plain(s string, segments bool) bool {
	for i := range len(s) {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '/' && segments:
		case strings.IndexByte("-_.~:", c) < 0:
			return false
		}
	}
	return true
}

func plainPURLString(purlType string, id PackageID) string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(purlType)
	for seg := range strings.SplitSeq(id.Namespace, "/") {
		if seg != "" {
			b.WriteByte('/')
			b.WriteString(seg)
		}
	}
	b.WriteByte('/')
	b.WriteString(id.Name)
	if id.Version != "" {
		b.WriteByte('@')
		b.WriteString(id.Version)
	}
	sep := byte('#')
	for seg := range strings.SplitSeq(id.Subpath, "/") {
		if seg != "" {
			b.WriteByte(sep)
			b.WriteString(seg)
			sep = '/'
		}
	}
	return b.String()
}

// QualifiedName returns the name that the ecosystem's users write, for
// example "@scope/name" for npm or "group:artifact" for Maven.
func (id PackageID) QualifiedName() string {
	name := id.Name
	switch {
	case id.Namespace == "":
	case id.Ecosystem == EcosystemMaven:
		name = id.Namespace + ":" + id.Name
	case id.Ecosystem == EcosystemVSCode, id.Ecosystem == EcosystemOpenVSX:
		name = id.Namespace + "." + id.Name
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

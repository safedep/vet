package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/package-url/packageurl-go"
	"github.com/safedep/dry/api/pb"
)

// PackageVersion is the identity of one package version. It keeps the name
// and the version as the manifest writes them, the raw form, and their
// canonical form under the rule of the ecosystem. dry/api/pb owns each rule.
//
// vet compares the canonical form and sends the raw form to a remote API,
// which folds it under its own rule. Compare two values with Equal, and key
// a map with Key. The type is not comparable, so == does not compile: it
// would compare the raw spelling.
type PackageVersion struct {
	_  [0]func()
	pv pb.PackageVersion
}

// PackageKey is a comparable key of a package version, or of a package with
// no version. It holds the ecosystem, the rule version and the canonical
// name and version, so a rule change never matches a key of an older rule.
type PackageKey string

// NewPackageVersion builds the identity of a package version from its raw
// name and version.
func NewPackageVersion(eco Ecosystem, name, version string) (PackageVersion, error) {
	value, ok := ecosystems[eco]
	if !ok {
		return PackageVersion{}, fmt.Errorf("unknown ecosystem %q", string(eco))
	}
	if name == "" {
		return PackageVersion{}, errors.New("package name is empty")
	}
	return PackageVersion{pv: pb.NewPackageVersionFromParts(value, name, version)}, nil
}

// MustPackageVersion is NewPackageVersion for a value that the code fixes,
// such as a constant or a test case. It panics on an error.
func MustPackageVersion(eco Ecosystem, name, version string) PackageVersion {
	p, err := NewPackageVersion(eco, name, version)
	if err != nil {
		panic(err)
	}
	return p
}

// ErrUnknownEcosystem means vet does not read the ecosystem of a PURL type.
// No enricher has data for it, so vet skips its packages.
var ErrUnknownEcosystem = errors.New("unknown ecosystem")

// purlTypes holds each PURL type that names an ecosystem vet reads.
// TestPURLTypesMatchDry checks that dry maps each one to that ecosystem.
var purlTypes = map[string]bool{
	"npm": true, "pypi": true, "pip": true, "maven": true, "golang": true, "go": true,
	"cargo": true, "gem": true, "rubygems": true, "nuget": true, "composer": true, "pub": true,
	"github": true, "actions": true, "githubactions": true, "terraform": true,
	"vscode": true, "vsix": true, "vsx": true, "openvsx": true,
}

// ParsePURL builds the identity of a package version from a package URL. The
// raw form is the name and the version as the PURL writes them. The PURL
// subpath is not part of the identity. A PURL type outside the ecosystems of
// vet gives an error that wraps ErrUnknownEcosystem.
func ParsePURL(s string) (PackageVersion, error) {
	if typ, ok := purlType(s); ok && !purlTypes[typ] {
		return PackageVersion{}, fmt.Errorf("%w: PURL type %q", ErrUnknownEcosystem, typ)
	}
	pv, err := pb.NewPackageVersionFromPurl(s)
	if err != nil {
		return PackageVersion{}, fmt.Errorf("parse PURL %q: %w", s, err)
	}
	if _, err := ecosystemOf(pv.Ecosystem()); err != nil {
		return PackageVersion{}, fmt.Errorf("parse PURL %q: %w", s, err)
	}
	if pv.RawName() == "" {
		return PackageVersion{}, fmt.Errorf("parse PURL %q: package name is empty", s)
	}
	return PackageVersion{pv: pv}, nil
}

// purlType returns the type of a PURL in lower case: the part after "pkg:"
// and its slashes, up to the next slash. It returns false for a string with
// no "pkg:" scheme.
func purlType(s string) (string, bool) {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || !strings.EqualFold(scheme, "pkg") {
		return "", false
	}
	typ, _, _ := strings.Cut(strings.TrimLeft(rest, "/"), "/")
	return strings.ToLower(typ), true
}

// IsZero reports the zero value, which names no package.
func (p PackageVersion) IsZero() bool {
	return p.pv.Ecosystem() == packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED
}

// Ecosystem is the ecosystem of the package.
func (p PackageVersion) Ecosystem() Ecosystem {
	e, err := ecosystemOf(p.pv.Ecosystem())
	if err != nil {
		return ""
	}
	return e
}

// Name is the canonical name, for logic.
func (p PackageVersion) Name() string { return p.pv.Name() }

// Version is the canonical version, for logic.
func (p PackageVersion) Version() string { return p.pv.Version() }

// RawName is the name as the manifest writes it, for display and for a
// remote API.
func (p PackageVersion) RawName() string { return p.pv.RawName() }

// RawVersion is the version as the manifest writes it, for display and for a
// remote API.
func (p PackageVersion) RawVersion() string { return p.pv.RawVersion() }

// Key is the key of the package version.
func (p PackageVersion) Key() PackageKey { return PackageKey(p.pv.Key()) }

// NameKey is the key of the package with no version. It groups the versions
// of one package.
func (p PackageVersion) NameKey() PackageKey { return PackageKey(p.pv.NameKey()) }

// Equal reports whether two values name one package version.
func (p PackageVersion) Equal(other PackageVersion) bool { return p.pv.Equal(other.pv) }

// SamePackage reports whether two values name one package, at any version.
func (p PackageVersion) SamePackage(other PackageVersion) bool { return p.NameKey() == other.NameKey() }

// Compare orders the version of p against the version of other under the
// rule of the ecosystem. It returns an error when the ecosystem has no order
// or the values name two packages. A caller that gets an error must not claim
// an order, for example an upgrade or a downgrade.
func (p PackageVersion) Compare(other PackageVersion) (int, error) { return p.pv.Compare(other.pv) }

// NameIs reports a name that names this package under the rule of the
// ecosystem, so "python-dateutil" names the PyPI package python.dateutil.
func (p PackageVersion) NameIs(name string) bool {
	n, err := canonicalName(p.Ecosystem(), name)
	return err == nil && n == p.Name()
}

// MatchName reports a canonical name that a glob matches. The glob has the
// syntax of path.Match, but * also matches a /, so "buf.build/gen/go/acme/*"
// matches each module under that path. The literal parts of the pattern
// fold under the rule of the ecosystem, so "acme-*" matches the PyPI name
// Acme.Utils.
func (p PackageVersion) MatchName(pattern string) (bool, error) {
	folded, err := foldPattern(p.Ecosystem(), pattern)
	if err != nil {
		return false, err
	}
	re, err := globRegexp(folded)
	if err != nil {
		return false, err
	}
	return re.MatchString(p.Name()), nil
}

// globRegexp turns a path.Match pattern into a regular expression in which
// * matches any text and ? matches one character, a / too.
func globRegexp(pattern string) (*regexp.Regexp, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '\\':
			i++
			if i < len(pattern) {
				b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			}
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			end := strings.IndexByte(pattern[i:], ']')
			b.WriteString(pattern[i : i+end+1])
			i += end
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// foldPattern folds the literal parts of a path.Match pattern. It keeps the
// wildcards and the character classes as they are.
func foldPattern(eco Ecosystem, pattern string) (string, error) {
	var out, lit strings.Builder
	flush := func() error {
		if lit.Len() == 0 {
			return nil
		}
		n, err := canonicalName(eco, lit.String())
		if err != nil {
			return err
		}
		for _, r := range n {
			if strings.ContainsRune(`*?[\`, r) {
				out.WriteByte('\\')
			}
			out.WriteRune(r)
		}
		lit.Reset()
		return nil
	}
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '*' || c == '?':
			if err := flush(); err != nil {
				return "", err
			}
			out.WriteByte(c)
		case c == '[':
			if err := flush(); err != nil {
				return "", err
			}
			end := strings.IndexByte(pattern[i:], ']')
			if end < 0 {
				return "", path.ErrBadPattern
			}
			out.WriteString(pattern[i : i+end+1])
			i += end
		case c == '\\' && i+1 < len(pattern):
			i++
			lit.WriteByte(pattern[i])
		default:
			lit.WriteByte(c)
		}
	}
	if err := flush(); err != nil {
		return "", err
	}
	return out.String(), nil
}

// canonicalName returns a name, or a part of a name, under the rule of the
// ecosystem.
func canonicalName(eco Ecosystem, name string) (string, error) {
	p, err := NewPackageVersion(eco, name, "")
	if err != nil {
		return "", err
	}
	return p.Name(), nil
}

// WithVersion returns the same package at another raw version.
func (p PackageVersion) WithVersion(version string) PackageVersion {
	return PackageVersion{pv: pb.NewPackageVersionFromParts(p.pv.Ecosystem(), p.pv.RawName(), version)}
}

// PURL is the package URL in the form of the purl-spec type definition. It
// keeps the version as the manifest writes it, because no purl-spec type
// folds a version. It is empty for a name that a PURL cannot hold. It parses
// back to the same identity, but it is not a key: use Key for a map or a
// store, and CanonicalPURL for one string across spellings.
func (p PackageVersion) PURL() string {
	urn := p.CanonicalPURL()
	if urn == "" || !p.pv.HasRule() {
		return urn
	}
	u, err := packageurl.FromString(urn)
	if err != nil {
		return ""
	}
	if fold, ok := purlSpecName[p.pv.Ecosystem()]; ok {
		u.Name = fold(p.RawName())
	}
	if p.pv.HasVersionRule() {
		u.Version = strings.TrimSpace(p.RawVersion())
	}
	return u.ToString()
}

// CanonicalPURL is the package URL of the canonical name and version. Two
// spellings of one package version give one CanonicalPURL.
func (p PackageVersion) CanonicalPURL() string {
	urn, err := p.pv.URN()
	if err != nil {
		return ""
	}
	return urn
}

// purlSpecName holds the name normalization of the purl-spec type
// definition for each ecosystem whose identity rule folds the name. A purl
// name can differ from the identity name: purl-spec keeps the dot of a PyPI
// name, and PEP 503 does not.
var purlSpecName = map[packagev1.Ecosystem]func(string) string{
	packagev1.Ecosystem_ECOSYSTEM_PYPI: func(name string) string {
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	},
}

// String is "<ecosystem>/<raw name>@<raw version>", for display.
func (p PackageVersion) String() string {
	s := string(p.Ecosystem()) + "/" + p.RawName()
	if v := p.RawVersion(); v != "" {
		s += "@" + v
	}
	return s
}

// RawProto is the wire form of the package version: the raw name and
// version. Only the clients of the SafeDep API call it.
func (p PackageVersion) RawProto() *packagev1.PackageVersion { return p.pv.RawProto() }

// packageVersionJSON is the JSON form. The canonical fields serve a reader of
// the report. A decoder rebuilds the value from the raw fields, so a newer
// rule applies to older JSON.
type packageVersionJSON struct {
	Ecosystem  Ecosystem `json:"ecosystem"`
	Name       string    `json:"name"`
	Version    string    `json:"version,omitempty"`
	RawName    string    `json:"raw_name"`
	RawVersion string    `json:"raw_version,omitempty"`
	PURL       string    `json:"purl,omitempty"`
}

// JSONSchemaAlias gives the report schema the JSON shape of a package
// version.
func (PackageVersion) JSONSchemaAlias() any { return packageVersionJSON{} }

// MarshalJSON writes the canonical and the raw form.
func (p PackageVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(packageVersionJSON{
		Ecosystem: p.Ecosystem(), Name: p.Name(), Version: p.Version(),
		RawName: p.RawName(), RawVersion: p.RawVersion(), PURL: p.PURL(),
	})
}

// UnmarshalJSON rebuilds the value from the ecosystem and the raw form.
func (p *PackageVersion) UnmarshalJSON(b []byte) error {
	var j packageVersionJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	v, err := NewPackageVersion(j.Ecosystem, j.RawName, j.RawVersion)
	if err != nil {
		return fmt.Errorf("decode package version: %w", err)
	}
	*p = v
	return nil
}

// PackagePattern selects packages by a PURL. A PURL with no version
// selects each version of the package. A name with *, ? or [ is a glob, as
// MatchName reads it.
type PackagePattern struct {
	id   PackageVersion
	glob bool
}

// ParsePackagePattern parses a PURL that can hold a name glob, as
// pkg:npm/@acme/* or pkg:golang/buf.build/gen/go/acme/*.
func ParsePackagePattern(purl string) (PackagePattern, error) {
	id, err := ParsePURL(purl)
	if err != nil {
		return PackagePattern{}, err
	}
	p := PackagePattern{id: id, glob: strings.ContainsAny(id.RawName(), "*?[")}
	if p.glob {
		if _, err := id.MatchName(id.RawName()); err != nil {
			return PackagePattern{}, fmt.Errorf("parse PURL %q: name glob: %w", purl, err)
		}
	}
	return p, nil
}

// Matches reports whether the pattern selects the package version.
func (p PackagePattern) Matches(id PackageVersion) bool {
	if id.Ecosystem() != p.id.Ecosystem() {
		return false
	}
	version := p.id.RawVersion()
	if !p.glob {
		if version == "" {
			return id.SamePackage(p.id)
		}
		return id.Equal(p.id)
	}
	if ok, err := id.MatchName(p.id.RawName()); err != nil || !ok {
		return false
	}
	return version == "" || id.Equal(id.WithVersion(version))
}

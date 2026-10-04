package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/safedep/vet/v2/model"
)

// Meta holds the fields that every constructor needs.
type Meta struct {
	ControlID   string
	Family      Family
	Severity    Severity
	Confidence  Confidence
	Title       string
	Description string
}

// Key holds the facts that tell two findings of one control on one subject
// apart. Decisions section 3.2 defines the key of each subject kind.
type Key struct {
	// Discriminator is the advisory id of a vulnerability, or the rule
	// discriminator of a file finding, for example the action name.
	Discriminator string
	// Occurrence tells identical snippets in one file apart.
	Occurrence int
}

// ForPackage returns a finding on a package version in a manifest.
func ForPackage(m Meta, manifestPath string, pkg *model.Package, key Key) Finding {
	s := &PackageSubject{
		PURL:         pkg.ID.PURL(),
		Ecosystem:    pkg.ID.Ecosystem(),
		Name:         pkg.ID.Name(),
		Version:      pkg.ID.Version(),
		RawName:      pkg.ID.RawName(),
		RawVersion:   pkg.ID.RawVersion(),
		Direct:       pkg.Direct,
		ManifestPath: manifestPath,
	}
	f := newFinding(m, Subject{Kind: SubjectPackage, Package: s})
	f.Change = pkg.Change
	if pkg.Line > 0 {
		f.Locus = &Locus{Path: manifestPath, StartLine: pkg.Line, EndLine: pkg.Line}
	}
	f.ID = computeID(m.ControlID, string(SubjectPackage), string(pkg.ID.Key()), manifestPath, key.Discriminator)
	return f
}

// ForFile returns a finding on a place in a file.
func ForFile(m Meta, locus Locus, key Key) Finding {
	f := newFinding(m, Subject{Kind: SubjectFile, File: &FileSubject{Path: locus.Path}})
	l := locus
	f.Locus = &l
	f.ID = computeID(m.ControlID, string(SubjectFile), locus.Path, key.Discriminator,
		NormalizeSnippet(locus.Snippet), strconv.Itoa(key.Occurrence))
	return f
}

// ForManifest returns a finding on a manifest as a whole.
func ForManifest(m Meta, manifestPath string, eco model.Ecosystem, key Key) Finding {
	f := newFinding(m, Subject{Kind: SubjectManifest, Manifest: &ManifestSubject{Path: manifestPath, Ecosystem: eco}})
	f.ID = computeID(m.ControlID, string(SubjectManifest), manifestPath, key.Discriminator)
	return f
}

// ForApplication returns a finding on an application root.
func ForApplication(m Meta, root, signatureID string) Finding {
	f := newFinding(m, Subject{Kind: SubjectApplication, Application: &ApplicationSubject{Root: root, SignatureID: signatureID}})
	f.ID = computeID(m.ControlID, string(SubjectApplication), root, signatureID)
	return f
}

func newFinding(m Meta, s Subject) Finding {
	conf := m.Confidence
	if conf == "" {
		conf = ConfidenceHigh
	}
	return Finding{
		ControlID:   m.ControlID,
		Family:      m.Family,
		Severity:    m.Severity,
		Confidence:  conf,
		Title:       m.Title,
		Description: m.Description,
		Subject:     s,
	}
}

// NormalizeSnippet collapses whitespace, so that a reformatted line keeps its id.
func NormalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// computeID hashes the key fields. The id leaves out the line number,
// severity, text, the vet version and times (decisions section 3.2).
func computeID(fields ...string) string {
	h := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return "f-" + hex.EncodeToString(h[:])[:16]
}

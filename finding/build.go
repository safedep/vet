package finding

import (
	"crypto/sha256"
	"encoding/hex"
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

// ForPackage returns a finding on a package version in a manifest.
func ForPackage(m Meta, manifestPath string, pkg *model.Package) Finding {
	s := &PackageSubject{
		PURL:         pkg.ID.PURL(),
		Ecosystem:    pkg.ID.Ecosystem,
		Name:         pkg.ID.QualifiedName(),
		Version:      pkg.ID.Version,
		Direct:       pkg.Direct,
		ManifestPath: manifestPath,
	}
	f := newFinding(m, Subject{Kind: SubjectPackage, Package: s})
	f.Change = pkg.Change
	if pkg.Line > 0 {
		f.Locus = &Locus{Path: manifestPath, StartLine: pkg.Line, EndLine: pkg.Line}
	}
	f.ID = computeID(m.ControlID, string(SubjectPackage), s.PURL)
	return f
}

// ForFile returns a finding on a place in a file.
func ForFile(m Meta, locus Locus) Finding {
	f := newFinding(m, Subject{Kind: SubjectFile, File: &FileSubject{Path: locus.Path}})
	l := locus
	f.Locus = &l
	f.ID = computeID(m.ControlID, string(SubjectFile), locus.Path)
	return f
}

// ForManifest returns a finding on a manifest as a whole.
func ForManifest(m Meta, manifestPath string, eco model.Ecosystem) Finding {
	f := newFinding(m, Subject{Kind: SubjectManifest, Manifest: &ManifestSubject{Path: manifestPath, Ecosystem: eco}})
	f.ID = computeID(m.ControlID, string(SubjectManifest), manifestPath)
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

func computeID(fields ...string) string {
	h := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return "f-" + hex.EncodeToString(h[:])[:16]
}

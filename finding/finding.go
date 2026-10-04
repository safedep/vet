package finding

import (
	"cmp"
	"errors"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/model"
)

// Finding is one problem that a control found.
type Finding struct {
	ID          string       `json:"id"`
	ControlID   string       `json:"control_id"`
	Family      Family       `json:"family"`
	Severity    Severity     `json:"severity"`
	Confidence  Confidence   `json:"confidence"`
	Subject     Subject      `json:"subject"`
	Locus       *Locus       `json:"locus,omitempty"`
	Change      model.Change `json:"change,omitempty"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Evidence    []Evidence   `json:"evidence,omitempty"`
	References  []string     `json:"references,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`
	Suppression *Suppression `json:"suppression,omitempty"`
	PolicyRule  string       `json:"policy_rule,omitempty"`
}

// Subject holds exactly one of its fields. Kind names it.
type Subject struct {
	Kind        SubjectKind         `json:"kind"`
	Package     *PackageSubject     `json:"package,omitempty"`
	File        *FileSubject        `json:"file,omitempty"`
	Manifest    *ManifestSubject    `json:"manifest,omitempty"`
	Application *ApplicationSubject `json:"application,omitempty"`
}

// PackageSubject is a package version in one manifest. PURL, Name and
// Version hold the canonical form, which a reader compares. RawName and
// RawVersion hold the form that the manifest writes.
type PackageSubject struct {
	PURL         string          `json:"purl"`
	Ecosystem    model.Ecosystem `json:"ecosystem"`
	Name         string          `json:"name"`
	Version      string          `json:"version,omitempty"`
	RawName      string          `json:"raw_name"`
	RawVersion   string          `json:"raw_version,omitempty"`
	Direct       bool            `json:"direct"`
	ManifestPath string          `json:"manifest_path"`
}

// PackageVersion rebuilds the identity of the package from the ecosystem and
// the raw form, so it compares under the current identity rule.
func (s *PackageSubject) PackageVersion() (model.PackageVersion, error) {
	return model.NewPackageVersion(s.Ecosystem, s.RawName, s.RawVersion)
}

// FileSubject is a file in the target, for example a workflow.
type FileSubject struct {
	Path string `json:"path"`
	// Element is the part of the file that is at fault, such as an action
	// ref, a trigger or an expression of a workflow. It is empty when the
	// finding is about the file as a whole.
	Element string `json:"element,omitempty"`
}

// ManifestSubject is a manifest file as a whole.
type ManifestSubject struct {
	Path      string          `json:"path"`
	Ecosystem model.Ecosystem `json:"ecosystem,omitempty"`
}

// ApplicationSubject is an application root, for example an AI agent project.
type ApplicationSubject struct {
	Root        string `json:"root"`
	SignatureID string `json:"signature_id,omitempty"`
}

// Locus is the place of the finding in a file.
type Locus struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// Evidence is one fact that supports the finding.
type Evidence struct {
	Source  string `json:"source"`
	Summary string `json:"summary"`
	URL     string `json:"url,omitempty"`
}

// Remediation tells the user how to fix the finding.
type Remediation struct {
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Command      string `json:"command,omitempty"`
}

// Suppression records the policy suppression that matched the finding. A
// suppressed finding stays in the report, and the gate ignores it.
type Suppression struct {
	Reason  string     `json:"reason"`
	Expires *time.Time `json:"expires,omitempty"`
	Rule    string     `json:"rule,omitempty"`
}

// Suppressed reports whether a policy suppressed the finding.
func (f *Finding) Suppressed() bool { return f.Suppression != nil }

// Validate checks the closed sets and the one-subject rule.
func (f *Finding) Validate() error {
	var errs []error
	if f.ID == "" {
		errs = append(errs, errors.New("id is empty"))
	}
	if f.ControlID == "" {
		errs = append(errs, errors.New("control_id is empty"))
	}
	if !f.Family.Valid() {
		errs = append(errs, fmt.Errorf("unknown family %q", f.Family))
	}
	if !f.Severity.Valid() {
		errs = append(errs, fmt.Errorf("unknown severity %q", f.Severity))
	}
	if !f.Confidence.Valid() {
		errs = append(errs, fmt.Errorf("unknown confidence %q", f.Confidence))
	}
	if !f.Change.Valid() {
		errs = append(errs, fmt.Errorf("unknown change %q", f.Change))
	}
	if f.Title == "" {
		errs = append(errs, errors.New("title is empty"))
	}
	if err := f.Subject.validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s Subject) validate() error {
	set := 0
	if s.Package != nil {
		set++
	}
	if s.File != nil {
		set++
	}
	if s.Manifest != nil {
		set++
	}
	if s.Application != nil {
		set++
	}
	if set != 1 {
		return fmt.Errorf("subject must hold exactly one field, got %d", set)
	}

	var ok bool
	switch s.Kind {
	case SubjectPackage:
		ok = s.Package != nil
	case SubjectFile:
		ok = s.File != nil
	case SubjectManifest:
		ok = s.Manifest != nil
	case SubjectApplication:
		ok = s.Application != nil
	}
	if !ok {
		return fmt.Errorf("subject kind %q does not match its field", s.Kind)
	}
	return nil
}

// Compare orders findings for a report: the most severe first, then by
// control and id. Every report source uses this order.
func Compare(a, b *Finding) int {
	if c := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

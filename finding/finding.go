package finding

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	Gate        *GateRecord  `json:"gate,omitempty"`
	// The engine sets Attack when the control of the finding is an attack
	// control. It reads the control info, so a control cannot set it.
	Attack *Attack `json:"attack,omitempty"`
	// Advisory is the id of the advisory of a vulnerability finding.
	Advisory string `json:"advisory,omitempty"`
	// The engine sets Reach on a vulnerability finding of a scan with
	// source code. A control cannot set it.
	Reach *Reach `json:"reach,omitempty"`
}

// ReachLevel says how far the code of the project reaches the package of a
// finding.
type ReachLevel string

const (
	// ReachCalled is a vulnerable function that a call path from an entry
	// point of the project reaches. Path holds the path.
	ReachCalled ReachLevel = "called"
	// ReachNotCalled is a vulnerable function that no call path reaches.
	// vet says it only when the symbol record names every fix site, a
	// maintainer verified the record, vet read the code of the package,
	// and the project alone imports the package.
	ReachNotCalled ReachLevel = "not-called"
	// ReachImported is a package that the code imports, or that the
	// dependency graph reaches from a package that the code imports.
	ReachImported ReachLevel = "imported"
	// ReachUnused is a package that no source file imports and that no
	// imported package depends on. A package that the project runs with no
	// import, as a build tool from a script, is unused too.
	ReachUnused ReachLevel = "unused"
	// ReachUnknown is a package that vet cannot place. Cause says why. A
	// report never shows it as safe.
	ReachUnknown ReachLevel = "unknown"
)

// ReachCause says why a reach is unknown, or what limits it.
type ReachCause string

const (
	// ReachNoGraph is a manifest with no dependency graph, so vet cannot
	// tell an unused package from a transitive one.
	ReachNoGraph ReachCause = "no-graph"
	// ReachDynamicImport is a project that imports a module by a computed
	// name in the language of the package.
	ReachDynamicImport ReachCause = "dynamic-import"
	// ReachBudget is an analysis that its time budget stopped.
	ReachBudget ReachCause = "budget"
	// ReachUnreadFiles is a project with a source file of the language of
	// the package that the analysis could not read, parse or index whole.
	ReachUnreadFiles ReachCause = "unread-files"
	// ReachNoSourceFiles is a project with no source file that vet parses
	// in the language of the package, such as a project of .jsx files.
	ReachNoSourceFiles ReachCause = "no-source-files"
	// ReachNoSymbolData is an imported package with no record of its
	// vulnerable functions, so function reach falls back to the import.
	ReachNoSymbolData ReachCause = "no-symbol-data"
	// ReachNoEntryPoint is a project where vet found no entry point, so it
	// searched from every exported function.
	ReachNoEntryPoint ReachCause = "no-entry-point"
	// ReachNoDependencySource is a package with no source on the disk, in
	// the vendor directory or in the module or crate cache.
	ReachNoDependencySource ReachCause = "no-dependency-source"
	// ReachNoSymbolInGraph is a record with a fix site that the call graph
	// of the code of the package does not hold.
	ReachNoSymbolInGraph ReachCause = "no-symbol-in-graph"
	// ReachBroadRecord is a record that does not name every fix site.
	ReachBroadRecord ReachCause = "broad-record"
	// ReachUnreviewedRecord is a record that no maintainer verified.
	ReachUnreviewedRecord ReachCause = "unreviewed-record"
	// ReachUnresolvedCall is a call path that ends at a call that vet
	// cannot resolve.
	ReachUnresolvedCall ReachCause = "unresolved-call"
	// ReachDynamicFlag is a call path through code that the call graph
	// marks dynamic, such as reflection, or a dynamic site in a file that
	// imports the package.
	ReachDynamicFlag ReachCause = "dynamic-flag"
	// ReachTransitive is a package that another dependency can call, so no
	// path in the code that vet read proves that nothing calls it.
	ReachTransitive ReachCause = "transitive"
	// ReachAnalysisFailed is a call graph search that failed.
	ReachAnalysisFailed ReachCause = "analysis-failed"
)

// Reach is the reach of the package of a finding.
type Reach struct {
	Level      ReachLevel `json:"level" jsonschema:"enum=called,enum=not-called,enum=imported,enum=unused,enum=unknown"`
	Cause      ReachCause `json:"cause,omitempty" jsonschema:"enum=no-graph,enum=dynamic-import,enum=budget,enum=unread-files,enum=no-source-files,enum=no-symbol-data,enum=no-entry-point,enum=no-dependency-source,enum=no-symbol-in-graph,enum=broad-record,enum=unreviewed-record,enum=unresolved-call,enum=dynamic-flag,enum=transitive,enum=analysis-failed"`
	Confidence Confidence `json:"confidence"`
	// Via is the dependency path from a package that the code imports to
	// the package of the finding, as PURLs, when no file imports it.
	Via []string `json:"via,omitempty"`
	// TestOnly marks a package that only test files import.
	TestOnly bool `json:"test_only,omitempty"`
	// Imports are the import lines of the package.
	Imports []model.ImportSite `json:"imports,omitempty"`
	// FixSites are the functions that hold the vulnerable code, from the
	// symbol record of the advisory.
	FixSites []string `json:"fix_sites,omitempty"`
	// Path is the call path from an entry point to a fix site.
	Path []model.PathHop `json:"path,omitempty"`
}

// Attack marks a finding of an attack control. The attacks gate fails on
// it, and a report shows it before the other findings.
type Attack struct {
	// Technique is the id of the attack technique.
	Technique string `json:"technique,omitempty"`
	// MITRE holds the MITRE ATT&CK technique ids, as T1027.
	MITRE []string `json:"mitre,omitempty"`
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

// GateAction is what the gate does with a finding.
type GateAction string

const (
	// GateActionFail means that the finding fails the gate.
	GateActionFail GateAction = "fail"
	// GateActionWarn means that a warn rule matched the finding, and the
	// finding does not fail the gate.
	GateActionWarn GateAction = "warn"
)

// GateRecord records why the gate fails or warns on a finding. A finding that
// no rule and no --fail-on value matches has no Gate, and neither has a
// suppressed finding.
type GateRecord struct {
	Action GateAction `json:"action"`
	// Rules are the policy rules that match with the action: each fail
	// rule, or the first warn rule.
	Rules []string `json:"rules,omitempty"`
	// Broken are the fail rules that did not evaluate. Each one fails the
	// finding, so that a rule that cannot run does not let it pass.
	Broken []string `json:"broken,omitempty"`
	// FailOn is the --fail-on value that fails the finding.
	FailOn string `json:"fail_on,omitempty"`
	// Help and Link come from the first rule in Rules.
	Help string `json:"help,omitempty"`
	Link string `json:"link,omitempty"`
}

// Valid reports whether the action is in the closed set.
func (a GateAction) Valid() bool { return a == GateActionFail || a == GateActionWarn }

// Label is "Blocked by" for a fail record and "Warned by" for a warn
// record.
func (g *GateRecord) Label() string {
	if g.Action == GateActionFail {
		return "Blocked by"
	}
	return "Warned by"
}

// Cause names the rules and the --fail-on value of the record, as in
// "policy rule no-malware and --fail-on high".
func (g *GateRecord) Cause() string {
	var parts []string
	switch len(g.Rules) {
	case 0:
	case 1:
		parts = append(parts, "policy rule "+g.Rules[0])
	default:
		parts = append(parts, "policy rules "+strings.Join(g.Rules, ", "))
	}
	for _, r := range g.Broken {
		parts = append(parts, "policy rule "+r+", which did not evaluate")
	}
	if g.FailOn != "" {
		parts = append(parts, "--fail-on "+g.FailOn)
	}
	return strings.Join(parts, " and ")
}

// Short names the rules and the --fail-on value of the record, as
// "no-malware, bad (broken), --fail-on high", for a narrow column.
func (g *GateRecord) Short() string {
	parts := slices.Clone(g.Rules)
	for _, r := range g.Broken {
		parts = append(parts, r+" (broken)")
	}
	if g.FailOn != "" {
		parts = append(parts, "--fail-on "+g.FailOn)
	}
	return strings.Join(parts, ", ")
}

// Equal reports whether two records are the same. Both can be nil.
func (g *GateRecord) Equal(o *GateRecord) bool {
	if g == nil || o == nil {
		return g == o
	}
	return g.Action == o.Action && slices.Equal(g.Rules, o.Rules) && slices.Equal(g.Broken, o.Broken) &&
		g.FailOn == o.FailOn && g.Help == o.Help && g.Link == o.Link
}

// Fails reports whether the finding fails the gate.
func (f *Finding) Fails() bool { return f.Gate != nil && f.Gate.Action == GateActionFail }

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
	if f.Gate != nil && !f.Gate.Action.Valid() {
		errs = append(errs, fmt.Errorf("unknown gate action %q", f.Gate.Action))
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

// Compare orders findings for a report: the attack findings first, then
// the most severe, then by control and id. Every report source uses this
// order, so that no output shows a vulnerability above an attack.
func Compare(a, b *Finding) int {
	if aa, ba := a.Attack != nil, b.Attack != nil; aa != ba {
		if aa {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

// Path returns the file of the finding: the path of its locus, else of its
// file, its manifest or the manifest of its package. It is empty for an
// application finding.
func (f *Finding) Path() string {
	switch {
	case f.Locus != nil && f.Locus.Path != "":
		return f.Locus.Path
	case f.Subject.File != nil:
		return f.Subject.File.Path
	case f.Subject.Manifest != nil:
		return f.Subject.Manifest.Path
	case f.Subject.Package != nil:
		return f.Subject.Package.ManifestPath
	}
	return ""
}

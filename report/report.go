package report

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

const (
	// SchemaVersion is the version of the report schema, not of vet. A
	// breaking change raises its major version and its URL.
	SchemaVersion = "1.0.0"

	// SchemaURL names the JSON Schema of this version.
	SchemaURL = "https://schemas.safedep.io/vet/report/v1/report.schema.json"

	// LineSchemaURL names the JSON Schema of one line of "-o jsonl".
	LineSchemaURL = "https://schemas.safedep.io/vet/report/v1/report-line.schema.json"
)

// Header is the first item of a report.
type Header struct {
	SchemaVersion string   `json:"schema_version"`
	Tool          Tool     `json:"tool"`
	Scan          ScanInfo `json:"scan"`
}

// Tool names the program that wrote the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanKind names the kind of scan.
type ScanKind string

const (
	ScanKindScan     ScanKind = "scan"
	ScanKindEndpoint ScanKind = "endpoint"
)

// ScanMode names how a scan treats the target.
type ScanMode string

const (
	ScanModeFull  ScanMode = "full"
	ScanModeDelta ScanMode = "delta"
)

// ScanInfo describes the scan that the report belongs to.
type ScanInfo struct {
	ID        string    `json:"id"`
	Kind      ScanKind  `json:"kind"`
	Mode      ScanMode  `json:"mode"`
	Target    string    `json:"target"`
	TargetKey string    `json:"target_key"`
	StartedAt time.Time `json:"started_at"`
	Continued bool      `json:"continued,omitempty"`
	BaseRef   string    `json:"base_ref,omitempty"`
	GitRef    string    `json:"git_ref,omitempty"`
	GitSHA    string    `json:"git_sha,omitempty"`
}

// Kind names the field that a record holds.
type Kind string

const (
	KindManifest   Kind = "manifest"
	KindPackage    Kind = "package"
	KindInventory  Kind = "inventory"
	KindFinding    Kind = "finding"
	KindDiagnostic Kind = "diagnostic"
	KindCapability Kind = "capability"
)

// Record holds exactly one of its fields. Kind names it.
type Record struct {
	Kind       Kind             `json:"kind"`
	Manifest   *model.Manifest  `json:"manifest,omitempty"`
	Package    *PackageEntry    `json:"package,omitempty"`
	Inventory  *InventoryItem   `json:"inventory,omitempty"`
	Finding    *finding.Finding `json:"finding,omitempty"`
	Diagnostic *Diagnostic      `json:"diagnostic,omitempty"`
	Capability *Capability      `json:"capability,omitempty"`
}

// PackageEntry is a package with the manifests that declare it. PURL
// follows the purl-spec type definition of the ecosystem.
type PackageEntry struct {
	PURL        string   `json:"purl"`
	ManifestIDs []string `json:"manifest_ids"`
	model.Package
}

// InventoryKind names the kind of an inventory item.
type InventoryKind string

const (
	InventoryAITool       InventoryKind = "ai-tool"
	InventoryMCPServer    InventoryKind = "mcp-server"
	InventorySkill        InventoryKind = "skill"
	InventoryEditorPlugin InventoryKind = "editor-plugin"
)

// InventoryItem is a tool on a machine that is not a package of a manifest:
// an AI tool, an MCP server, an agent skill or an editor plugin (decisions P5).
type InventoryItem struct {
	Kind    InventoryKind     `json:"kind"`
	Name    string            `json:"name"`
	Version string            `json:"version,omitempty"`
	Path    string            `json:"path,omitempty"`
	Client  string            `json:"client,omitempty"`
	Scope   string            `json:"scope,omitempty"`
	Change  model.Change      `json:"change,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// Capability is a behavior of the application that a code signature finds,
// such as a call to the SDK of an LLM provider. The capabilities of a scan
// are its xBOM. The ID is the signature id.
type Capability struct {
	ID          string       `json:"id"`
	Description string       `json:"description,omitempty"`
	Vendor      string       `json:"vendor,omitempty"`
	Product     string       `json:"product,omitempty"`
	Service     string       `json:"service,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
	Change      model.Change `json:"change,omitempty"`
	// Occurrences are the calls that match the signature, at most a
	// bounded number of them.
	Occurrences []Occurrence `json:"occurrences"`
}

// HasTag reports whether the signature of the capability has a tag.
func (c *Capability) HasTag(tag string) bool { return slices.Contains(c.Tags, tag) }

// minShortID is the length of a short finding id: "f-" and 8 hex digits.
const minShortID = 10

// ShortIDLength is the length of the shortest prefix that tells each
// finding id apart from the others, and at least ten characters. vet
// report finding show accepts the prefix.
func ShortIDLength(ids []string) int {
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	n := minShortID
	for i := 1; i < len(sorted); i++ {
		a, b := sorted[i-1], sorted[i]
		common := 0
		for common < min(len(a), len(b)) && a[common] == b[common] {
			common++
		}
		n = max(n, common+1)
	}
	return n
}

// ShortID cuts id to n characters.
func ShortID(id string, n int) string { return id[:min(n, len(id))] }

// The signature tags that set the kind of a capability, and the tag of a
// weak algorithm.
const (
	TagAI     = "ai"
	TagCrypto = "cryptography"
	TagWeak   = "weak"
)

// CapabilityKind groups the capabilities for a reader: the AI BOM, the
// CBOM and the rest.
type CapabilityKind string

const (
	CapabilityAI     CapabilityKind = "ai"
	CapabilityCrypto CapabilityKind = "crypto"
	CapabilityOther  CapabilityKind = "other"
)

// Name is the short name of the capability for a reader: the product and
// the service, or the id.
func (c *Capability) Name() string {
	switch {
	case c.Product == "":
		return c.ID
	case c.Service == "" || c.Service == c.Product:
		return c.Product
	}
	return c.Product + " " + c.Service
}

// DetailTags returns the tags other than the tag that sets the kind, as
// llm or hash.
func (c *Capability) DetailTags() []string {
	var out []string
	for _, t := range c.Tags {
		if t != TagAI && t != TagCrypto {
			out = append(out, t)
		}
	}
	return out
}

// Kind returns the group of the capability, from its tags.
func (c *Capability) Kind() CapabilityKind {
	switch {
	case c.HasTag(TagAI):
		return CapabilityAI
	case c.HasTag(TagCrypto):
		return CapabilityCrypto
	}
	return CapabilityOther
}

// CompareCapabilities orders capabilities for a reader: AI first, then
// weak crypto, then the other crypto, then the rest, each by id.
func CompareCapabilities(a, b *Capability) int {
	rank := func(c *Capability) int {
		switch c.Kind() {
		case CapabilityAI:
			return 0
		case CapabilityCrypto:
			if c.HasTag(TagWeak) {
				return 1
			}
			return 2
		}
		return 3
	}
	return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a.ID, b.ID))
}

// Occurrence is one call in the source code that matches a signature.
type Occurrence struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Language string `json:"language,omitempty"`
	// Callee is the name of the called function, as the call graph
	// resolves it, such as openai//OpenAI.
	Callee string `json:"callee,omitempty"`
}

// DiagnosticLevel is the level of a diagnostic.
type DiagnosticLevel string

const (
	DiagnosticWarning DiagnosticLevel = "warning"
	DiagnosticError   DiagnosticLevel = "error"
)

// Diagnostic records an error or a limit that did not stop the scan, for
// example an enrichment backend that did not answer.
type Diagnostic struct {
	Level     DiagnosticLevel `json:"level"`
	Code      string          `json:"code"`
	Component string          `json:"component"`
	Message   string          `json:"message"`
	Count     int             `json:"count,omitempty"`
}

// Trailer is the last item of a report.
type Trailer struct {
	Summary     Summary   `json:"summary"`
	Gate        Gate      `json:"gate"`
	RecordCount uint64    `json:"record_count"`
	FinishedAt  time.Time `json:"finished_at"`
}

// Summary counts the records of a report.
type Summary struct {
	Manifests    int                      `json:"manifests"`
	Packages     int                      `json:"packages"`
	Inventory    int                      `json:"inventory"`
	Capabilities int                      `json:"capabilities"`
	Findings     int                      `json:"findings"`
	Suppressed   int                      `json:"suppressed"`
	Diagnostics  int                      `json:"diagnostics"`
	BySeverity   map[finding.Severity]int `json:"by_severity"`
	ByFamily     map[finding.Family]int   `json:"by_family"`
}

// GateOutcome is the result of the gate.
type GateOutcome string

const (
	// GateNone means that the user set no gate.
	GateNone GateOutcome = "NONE"
	GatePass GateOutcome = "PASS"
	GateFail GateOutcome = "FAIL"
)

// FailOn is the --fail-on value of a gate: a severity, or attacks.
type FailOn string

// FailOnAttacks fails the gate on the findings of the attack controls, and
// on no other finding.
const FailOnAttacks FailOn = "attacks"

// FailOnValues returns each --fail-on value, attacks first.
func FailOnValues() []FailOn {
	out := []FailOn{FailOnAttacks}
	for _, s := range finding.Severities() {
		out = append(out, FailOn(s))
	}
	return out
}

// ParseFailOn reads a --fail-on value.
func ParseFailOn(v string) (FailOn, error) {
	f := FailOn(strings.ToLower(strings.TrimSpace(v)))
	if f == FailOnAttacks {
		return f, nil
	}
	if _, ok := f.Severity(); ok {
		return f, nil
	}
	return "", fmt.Errorf("unknown --fail-on value %q: use attacks, critical, high, medium, low or info", v)
}

// Severity returns the severity of a severity value. It is false for
// attacks.
func (f FailOn) Severity() (finding.Severity, bool) {
	s := finding.Severity(f)
	return s, s.Valid()
}

// Gate is the outcome of the gate and what decided it.
type Gate struct {
	Outcome    GateOutcome `json:"outcome"`
	FailOn     FailOn      `json:"fail_on,omitempty"`
	Policy     string      `json:"policy,omitempty"`
	Rules      []string    `json:"rules,omitempty"`
	FindingIDs []string    `json:"finding_ids,omitempty"`
}

// ManifestRecord returns a record that holds a manifest.
func ManifestRecord(m *model.Manifest) Record { return Record{Kind: KindManifest, Manifest: m} }

// PackageRecord returns a record that holds a package entry.
func PackageRecord(p *PackageEntry) Record { return Record{Kind: KindPackage, Package: p} }

// InventoryRecord returns a record that holds an inventory item.
func InventoryRecord(i *InventoryItem) Record { return Record{Kind: KindInventory, Inventory: i} }

// CapabilityRecord returns a record that holds a capability.
func CapabilityRecord(c *Capability) Record { return Record{Kind: KindCapability, Capability: c} }

// FindingRecord returns a record that holds a finding.
func FindingRecord(f *finding.Finding) Record { return Record{Kind: KindFinding, Finding: f} }

// DiagnosticRecord returns a record that holds a diagnostic.
func DiagnosticRecord(d *Diagnostic) Record { return Record{Kind: KindDiagnostic, Diagnostic: d} }

// Validate checks that the record holds exactly the field that Kind names.
func (r Record) Validate() error {
	set := map[Kind]bool{
		KindManifest:   r.Manifest != nil,
		KindPackage:    r.Package != nil,
		KindInventory:  r.Inventory != nil,
		KindFinding:    r.Finding != nil,
		KindDiagnostic: r.Diagnostic != nil,
		KindCapability: r.Capability != nil,
	}
	n := 0
	for _, v := range set {
		if v {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("record must hold exactly one field, got %d", n)
	}
	if !set[r.Kind] {
		return fmt.Errorf("record kind %q does not match its field", r.Kind)
	}
	if r.Finding != nil {
		return r.Finding.Validate()
	}
	return nil
}

// NewSummary returns an empty summary.
func NewSummary() Summary {
	return Summary{BySeverity: map[finding.Severity]int{}, ByFamily: map[finding.Family]int{}}
}

// Add counts one record in the summary.
func (s *Summary) Add(r Record) {
	if s.BySeverity == nil || s.ByFamily == nil {
		*s = mergeSummary(NewSummary(), *s)
	}
	switch r.Kind {
	case KindManifest:
		s.Manifests++
	case KindPackage:
		s.Packages++
	case KindInventory:
		s.Inventory++
	case KindCapability:
		s.Capabilities++
	case KindDiagnostic:
		s.Diagnostics++
	case KindFinding:
		if r.Finding.Suppressed() {
			s.Suppressed++
			return
		}
		s.Findings++
		s.BySeverity[r.Finding.Severity]++
		s.ByFamily[r.Finding.Family]++
	}
}

func mergeSummary(dst, src Summary) Summary {
	dst.Manifests, dst.Packages, dst.Inventory, dst.Capabilities = src.Manifests, src.Packages, src.Inventory, src.Capabilities
	dst.Findings, dst.Suppressed, dst.Diagnostics = src.Findings, src.Suppressed, src.Diagnostics
	for k, v := range src.BySeverity {
		dst.BySeverity[k] = v
	}
	for k, v := range src.ByFamily {
		dst.ByFamily[k] = v
	}
	return dst
}

// ErrIncomplete reports a stream whose record count does not match its trailer.
var ErrIncomplete = errors.New("report stream is incomplete")

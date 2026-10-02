package plugin

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"iter"

	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// ErrUnavailable reports a remote backend that does not answer. A control
// that needs its data fails open: the scan continues with a diagnostic.
var ErrUnavailable = errors.New("plugin: backend unavailable")

// ArtifactKind names the kind of an artifact that a source yields.
type ArtifactKind string

const (
	ArtifactDirectory ArtifactKind = "directory"
	ArtifactImage     ArtifactKind = "image"
	ArtifactSBOM      ArtifactKind = "sbom"
	ArtifactPURL      ArtifactKind = "purl"
	ArtifactEndpoint  ArtifactKind = "endpoint"
)

// Artifact is one input to scan.
type Artifact struct {
	Kind ArtifactKind
	// Root is the file system to extract from. It is nil for a PURL.
	Root fs.FS
	// Path is the root on disk, when the artifact is on disk.
	Path string
	// Label is the target as the user typed it.
	Label string
	// Key is the canonical target key, for example the real absolute path.
	Key string
	// PURL is set for a PURL artifact.
	PURL string
	// Include limits the files that the engine reads to these paths in
	// Root, for example the one file of an SBOM artifact. Empty means every
	// file.
	Include []string
	// Manifests holds the manifests that the source reads itself, such as
	// the IDE extensions and the global packages of an endpoint. The engine
	// commits them with the manifests that it extracts.
	Manifests []*model.Manifest
	// Inventory holds the tools that the source finds that are not
	// packages, such as the MCP servers and the agent skills of an
	// endpoint (decisions P5).
	Inventory []report.InventoryItem
	// Close frees what the artifact holds, such as a clone or an image. It
	// is nil when there is nothing to free. The engine calls it after the
	// extraction.
	Close func() error
}

// Source enumerates the artifacts to scan: a directory, a repository, an
// image, an SBOM, a PURL or the endpoint.
type Source interface {
	Artifacts(ctx context.Context) iter.Seq2[Artifact, error]
}

// Extractor is Scalibr's filesystem.Extractor. vet defines no second one, so
// an extractor works in vet and in Scalibr with no rewrite.
type Extractor = filesystem.Extractor

// Enricher sets data fields on a batch of packages.
type Enricher interface {
	Enrich(ctx context.Context, pkgs []*model.Package) error
}

// PackageQuery selects packages from State.
type PackageQuery struct {
	ManifestID  string
	Ecosystem   model.Ecosystem
	ChangedOnly bool
}

// FindingQuery selects findings from State.
type FindingQuery struct {
	ControlID         string
	MinSeverity       finding.Severity
	IncludeSuppressed bool
}

// State is the streaming read view of the current scan. No method holds the
// full scan in memory.
type State interface {
	Manifests(ctx context.Context) iter.Seq2[*model.Manifest, error]
	Packages(ctx context.Context, q PackageQuery) iter.Seq2[*model.Package, error]
	Package(ctx context.Context, id model.PackageID) (*model.Package, error)
	Dependents(ctx context.Context, id model.PackageID) iter.Seq2[*model.Package, error]
	Findings(ctx context.Context, q FindingQuery) iter.Seq2[*finding.Finding, error]
}

// Control evaluates one manifest, loaded with its packages, and returns
// findings. A control that looks across manifests reads State.
type Control interface {
	Evaluate(ctx context.Context, m *model.Manifest, s State) ([]finding.Finding, error)
}

// ControlInfo describes one control id that a control plugin emits.
type ControlInfo struct {
	ID          string           `json:"id"`
	Family      finding.Family   `json:"family"`
	Severity    finding.Severity `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
}

// Describer lists the control ids that a control plugin emits. Every control
// plugin implements it, for "vet policy control list". plugintest checks it.
type Describer interface {
	Controls() []ControlInfo
}

// Report is the read view of a completed scan.
type Report interface {
	State
	Header() *report.Header
	Trailer() *report.Trailer
	// Records yields every record in the report order.
	Records(ctx context.Context) iter.Seq2[*report.Record, error]
}

// Sink writes one report format to w. It reads the report as a stream. The
// engine opens w: stdout for -o, or a temporary file that it renames into
// place for --report.
type Sink interface {
	Write(ctx context.Context, r Report, w io.Writer) error
}

// StreamSink is optional. A sink that implements it gets the header, each
// record as it commits, and the trailer, the way io.WriterTo is optional for
// io.Copy.
type StreamSink interface {
	Sink
	Begin(ctx context.Context, h *report.Header, w io.Writer) error
	Record(ctx context.Context, r *report.Record, w io.Writer) error
	End(ctx context.Context, t *report.Trailer, w io.Writer) error
}

// PolicyDoc is one policy v2 document.
type PolicyDoc struct {
	// Name names the origin of the document, for example a file path.
	Name    string
	Content []byte
}

// PolicySource loads policy v2 documents.
type PolicySource interface {
	Policies(ctx context.Context) ([]PolicyDoc, error)
}

// Checker is optional. A plugin that implements it can refuse to run before
// the scan starts, for example a stub of a backend that does not exist yet.
// A sink that refuses makes the command exit with a usage error.
type Checker interface {
	Check() error
}

// Config is the plugin's own options section, plugins.<name>.options.
type Config interface {
	// Decode decodes the options into v. An unknown key is an error.
	Decode(v any) error
}

// Schemer is optional. A plugin that implements it adds its options to
// "vet config schema get".
type Schemer interface {
	OptionsSchema() []byte
}

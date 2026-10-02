// Package reportdoc holds a saved report in memory, from a scan file or a
// report file. It implements plugin.Report, so every sink renders it, and
// the store of the policy, so "vet report show --policy" can apply a new
// gate without a change to the saved scan.
//
// The trade-off: the report sits in memory. A saved scan with many
// packages costs memory in proportion, which a scan does not.
package reportdoc

import (
	"context"
	"iter"
	"slices"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Doc is a report in memory.
type Doc struct {
	header    report.Header
	trailer   report.Trailer
	manifests []*model.Manifest
	packages  []*report.PackageEntry
	inventory []*report.InventoryItem
	findings  []*finding.Finding
	diags     []*report.Diagnostic
}

// FromDocument holds a report that report.Read decoded.
func FromDocument(d *report.Document) *Doc {
	out := &Doc{header: d.Header, trailer: d.Trailer}
	for i := range d.Records {
		out.add(&d.Records[i])
	}
	out.link()
	return out
}

// Load reads every record of a report into memory.
func Load(ctx context.Context, r plugin.Report) (*Doc, error) {
	out := &Doc{}
	if h := r.Header(); h != nil {
		out.header = *h
	}
	if t := r.Trailer(); t != nil {
		out.trailer = *t
	}
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return nil, err
		}
		out.add(rec)
	}
	out.link()
	return out, nil
}

func (d *Doc) add(r *report.Record) {
	switch {
	case r.Manifest != nil:
		d.manifests = append(d.manifests, r.Manifest)
	case r.Package != nil:
		d.packages = append(d.packages, r.Package)
	case r.Inventory != nil:
		d.inventory = append(d.inventory, r.Inventory)
	case r.Finding != nil:
		d.findings = append(d.findings, r.Finding)
	case r.Diagnostic != nil:
		d.diags = append(d.diags, r.Diagnostic)
	}
}

// link puts each package into its manifests, as a scan file does.
func (d *Doc) link() {
	byID := map[string]*model.Manifest{}
	for _, m := range d.manifests {
		m.Packages = nil
		byID[m.ID] = m
	}
	for _, e := range d.packages {
		for _, id := range e.ManifestIDs {
			if m, ok := byID[id]; ok {
				p := e.Package
				m.Packages = append(m.Packages, &p)
			}
		}
	}
	slices.SortStableFunc(d.findings, finding.Compare)
}

// Header returns the header.
func (d *Doc) Header() *report.Header { return &d.header }

// Trailer returns the trailer.
func (d *Doc) Trailer() *report.Trailer { return &d.trailer }

// SetGate sets the gate and counts the records again.
func (d *Doc) SetGate(g report.Gate, now time.Time) {
	sum := report.NewSummary()
	var n uint64
	for r := range d.records() {
		sum.Add(*r)
		n++
	}
	d.trailer = report.Trailer{Summary: sum, Gate: g, RecordCount: n, FinishedAt: now.UTC()}
}

// Records yields the records in the report order.
func (d *Doc) Records(ctx context.Context) iter.Seq2[*report.Record, error] {
	return func(yield func(*report.Record, error) bool) {
		for r := range d.records() {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(r, nil) {
				return
			}
		}
	}
}

func (d *Doc) records() iter.Seq[*report.Record] {
	return func(yield func(*report.Record) bool) {
		for _, m := range d.manifests {
			r := report.ManifestRecord(m)
			if !yield(&r) {
				return
			}
		}
		for _, p := range d.packages {
			r := report.PackageRecord(p)
			if !yield(&r) {
				return
			}
		}
		for _, i := range d.inventory {
			r := report.InventoryRecord(i)
			if !yield(&r) {
				return
			}
		}
		for _, f := range d.findings {
			r := report.FindingRecord(f)
			if !yield(&r) {
				return
			}
		}
		for _, x := range d.diags {
			r := report.DiagnosticRecord(x)
			if !yield(&r) {
				return
			}
		}
	}
}

// Manifests yields the manifests with their packages.
func (d *Doc) Manifests(context.Context) iter.Seq2[*model.Manifest, error] {
	return func(yield func(*model.Manifest, error) bool) {
		for _, m := range d.manifests {
			if !yield(m, nil) {
				return
			}
		}
	}
}

// Packages yields the packages that match the query.
func (d *Doc) Packages(_ context.Context, q plugin.PackageQuery) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		for _, e := range d.packages {
			p := e.Package
			switch {
			case q.ManifestID != "" && !slices.Contains(e.ManifestIDs, q.ManifestID):
				continue
			case q.Ecosystem != "" && p.ID.Ecosystem != q.Ecosystem:
				continue
			case q.ChangedOnly && !p.Change.Introduces():
				continue
			}
			if !yield(&p, nil) {
				return
			}
		}
	}
}

// Package returns one package, or nil.
func (d *Doc) Package(_ context.Context, id model.PackageID) (*model.Package, error) {
	for _, e := range d.packages {
		if e.ID == id {
			p := e.Package
			return &p, nil
		}
	}
	return nil, nil
}

// Dependents yields the packages that depend on a package. A saved report
// holds no graph edges, so it yields nothing.
func (d *Doc) Dependents(context.Context, model.PackageID) iter.Seq2[*model.Package, error] {
	return func(func(*model.Package, error) bool) {}
}

// Findings yields the findings that match the query, the most severe
// first.
func (d *Doc) Findings(_ context.Context, q plugin.FindingQuery) iter.Seq2[*finding.Finding, error] {
	return func(yield func(*finding.Finding, error) bool) {
		for _, f := range d.findings {
			switch {
			case q.ControlID != "" && f.ControlID != q.ControlID:
				continue
			case q.MinSeverity != "" && !f.Severity.AtLeast(q.MinSeverity):
				continue
			case !q.IncludeSuppressed && f.Suppressed():
				continue
			}
			if !yield(f, nil) {
				return
			}
		}
	}
}

// Finding returns the finding with an id, or nil.
func (d *Doc) Finding(id string) *finding.Finding {
	for _, f := range d.findings {
		if f.ID == id {
			return f
		}
	}
	return nil
}

// FindingManifest returns the id of the manifest of a finding: the
// manifest of its package, or the manifest of its file. It is "" for a
// finding with neither.
func (d *Doc) FindingManifest(_ context.Context, id string) (string, error) {
	f := d.Finding(id)
	if f == nil {
		return "", nil
	}
	path := ""
	switch {
	case f.Subject.Package != nil:
		path = f.Subject.Package.ManifestPath
	case f.Subject.File != nil:
		path = f.Subject.File.Path
	case f.Subject.Manifest != nil:
		path = f.Subject.Manifest.Path
	}
	for _, m := range d.manifests {
		if m.Path == path {
			return m.ID, nil
		}
	}
	return "", nil
}

// Manifest returns a manifest by id, or nil.
func (d *Doc) Manifest(_ context.Context, id string) (*model.Manifest, error) {
	for _, m := range d.manifests {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, nil
}

// ReplaceFinding keeps the new suppression and rule of a finding.
func (d *Doc) ReplaceFinding(_ context.Context, _ string, f *finding.Finding) error {
	for i, g := range d.findings {
		if g.ID == f.ID {
			d.findings[i] = f
		}
	}
	return nil
}

// AddDiagnostic adds a diagnostic.
func (d *Doc) AddDiagnostic(_ context.Context, x *report.Diagnostic) error {
	d.diags = append(d.diags, x)
	return nil
}

var _ plugin.Report = (*Doc)(nil)

package plugintest

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"sort"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// MemState is an in-memory plugin.State and plugin.Report.
type MemState struct {
	ManifestList   []*model.Manifest
	FindingList    []*finding.Finding
	InventoryList  []*report.InventoryItem
	CapabilityList []*report.Capability
	DiagnosticList []*report.Diagnostic
	HeaderValue    *report.Header
	TrailerValue   *report.Trailer
}

var _ plugin.Report = (*MemState)(nil)

// NewMemState returns a state that holds the manifests.
func NewMemState(manifests ...*model.Manifest) *MemState {
	return &MemState{ManifestList: manifests}
}

// Manifests yields the manifests in insertion order.
func (s *MemState) Manifests(ctx context.Context) iter.Seq2[*model.Manifest, error] {
	return func(yield func(*model.Manifest, error) bool) {
		for _, m := range s.ManifestList {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(m, nil) {
				return
			}
		}
	}
}

// Packages yields the packages that match the query.
func (s *MemState) Packages(ctx context.Context, q plugin.PackageQuery) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		for _, m := range s.ManifestList {
			if q.ManifestID != "" && m.ID != q.ManifestID {
				continue
			}
			for _, p := range m.Packages {
				if err := ctx.Err(); err != nil {
					yield(nil, err)
					return
				}
				if q.Ecosystem != "" && p.ID.Ecosystem() != q.Ecosystem {
					continue
				}
				if q.ChangedOnly && !p.Change.Introduces() {
					continue
				}
				if !yield(p, nil) {
					return
				}
			}
		}
	}
}

// Capabilities yields the capabilities in insertion order.
func (s *MemState) Capabilities(ctx context.Context) iter.Seq2[*report.Capability, error] {
	return yieldAll(ctx, s.CapabilityList)
}

// Package returns the first package with the identity.
func (s *MemState) Package(_ context.Context, id model.PackageVersion) (*model.Package, error) {
	for _, m := range s.ManifestList {
		if p := m.Package(id); p != nil {
			return p, nil
		}
	}
	return nil, fmt.Errorf("package %s: not found", id)
}

// Dependents yields the packages that depend on the identity in any manifest graph.
func (s *MemState) Dependents(_ context.Context, id model.PackageVersion) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		for _, m := range s.ManifestList {
			if m.Graph == nil {
				continue
			}
			for _, parent := range m.Graph.Parents(id) {
				if p := m.Package(parent); p != nil {
					if !yield(p, nil) {
						return
					}
				}
			}
		}
	}
}

// Findings yields the findings that match the query.
func (s *MemState) Findings(_ context.Context, q plugin.FindingQuery) iter.Seq2[*finding.Finding, error] {
	return func(yield func(*finding.Finding, error) bool) {
		for _, f := range s.sortedFindings() {
			if q.ControlID != "" && f.ControlID != q.ControlID {
				continue
			}
			if q.MinSeverity != "" && !f.Severity.AtLeast(q.MinSeverity) {
				continue
			}
			if f.Suppressed() && !q.IncludeSuppressed {
				continue
			}
			if !yield(f, nil) {
				return
			}
		}
	}
}

// Header returns the header. A missing header gets a fixed test header.
func (s *MemState) Header() *report.Header {
	if s.HeaderValue == nil {
		s.HeaderValue = &report.Header{
			SchemaVersion: report.SchemaVersion,
			Tool:          report.Tool{Name: "vet", Version: "test"},
			Scan: report.ScanInfo{
				ID: "test0000scan", Kind: report.ScanKindScan, Mode: report.ScanModeFull,
				Target: ".", TargetKey: "/test", StartedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			},
		}
	}
	return s.HeaderValue
}

// Trailer returns the trailer. A missing trailer is computed from the records.
func (s *MemState) Trailer() *report.Trailer {
	if s.TrailerValue == nil {
		sum := report.NewSummary()
		var n uint64
		for r := range s.records() {
			sum.Add(*r)
			n++
		}
		s.TrailerValue = &report.Trailer{
			Summary:     sum,
			Gate:        report.Gate{Outcome: report.GateNone},
			RecordCount: n,
			FinishedAt:  time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC),
		}
	}
	return s.TrailerValue
}

// Records yields the manifests, the packages, the inventory, the findings
// and the diagnostics, in that order. Findings come in finding.Compare order.
func (s *MemState) Records(ctx context.Context) iter.Seq2[*report.Record, error] {
	return func(yield func(*report.Record, error) bool) {
		for r := range s.records() {
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

func (s *MemState) records() iter.Seq[*report.Record] {
	return func(yield func(*report.Record) bool) {
		for _, m := range s.ManifestList {
			r := report.ManifestRecord(m)
			if !yield(&r) {
				return
			}
		}
		for _, e := range s.packageEntries() {
			r := report.PackageRecord(e)
			if !yield(&r) {
				return
			}
		}
		for _, i := range s.InventoryList {
			r := report.InventoryRecord(i)
			if !yield(&r) {
				return
			}
		}
		for _, c := range s.CapabilityList {
			r := report.CapabilityRecord(c)
			if !yield(&r) {
				return
			}
		}
		for _, f := range s.sortedFindings() {
			r := report.FindingRecord(f)
			if !yield(&r) {
				return
			}
		}
		for _, d := range s.DiagnosticList {
			r := report.DiagnosticRecord(d)
			if !yield(&r) {
				return
			}
		}
	}
}

func (s *MemState) sortedFindings() []*finding.Finding {
	return slices.SortedStableFunc(slices.Values(s.FindingList), finding.Compare)
}

func (s *MemState) packageEntries() []*report.PackageEntry {
	byPURL := map[string]*report.PackageEntry{}
	for _, m := range s.ManifestList {
		for _, p := range m.Packages {
			purl := p.ID.PURL()
			e, ok := byPURL[purl]
			if !ok {
				e = &report.PackageEntry{PURL: purl, Package: *p}
				byPURL[purl] = e
			}
			e.ManifestIDs = append(e.ManifestIDs, m.ID)
		}
	}
	out := make([]*report.PackageEntry, 0, len(byPURL))
	for _, e := range byPURL {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out
}

func yieldAll[T any](ctx context.Context, items []T) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for _, it := range items {
			if err := ctx.Err(); err != nil {
				var zero T
				yield(zero, err)
				return
			}
			if !yield(it, nil) {
				return
			}
		}
	}
}

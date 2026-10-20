package engine

import (
	"context"
	"errors"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// sourceDir returns the directory of the source code of the scan, or "".
// Only a directory artifact, a local directory or a git clone, has code.
func (r *run) sourceDir() string {
	if len(r.artifacts) == 0 || r.artifacts[0].Kind != plugin.ArtifactDirectory {
		return ""
	}
	return r.artifacts[0].Path
}

// bindSource gives each source enricher the directory of the code, and
// records the reach of the scan in its header.
func (r *run) bindSource(ctx context.Context) error {
	dir := r.sourceDir()
	for _, e := range r.o.Enrichers {
		if s, ok := e.Plugin.(plugin.SourceEnricher); ok {
			s.UseSource(dir)
		}
	}
	r.reach = r.o.Reach
	switch {
	case r.reach.Level == "" || r.reach.Level == report.ReachOff:
		r.reach = report.ReachInfo{Level: report.ReachOff, Status: report.ReachNotComputed}
	case dir == "":
		r.reach.Status = report.ReachNoSource
	case r.reach.Status != "":
	default:
		r.reach.Status = report.ReachComputed
	}
	return r.writeReach(ctx)
}

// sourceFailed records that a source enricher failed, so the scan
// computes no reach and its header says why.
func (r *run) sourceFailed(e Enricher, err error) {
	if _, ok := e.Plugin.(plugin.SourceEnricher); !ok || r.reach.Status != report.ReachComputed {
		return
	}
	r.reach.Status = report.ReachFailed
	if errors.Is(err, plugin.ErrUnavailable) {
		r.reach.Status = report.ReachUnavailable
	}
	r.reachChanged = true
}

// symbolBundle records the symbol data that a source enricher read.
func (r *run) symbolBundle() {
	for _, e := range r.o.Enrichers {
		if s, ok := e.Plugin.(plugin.SymbolReporter); ok {
			if b := s.SymbolBundle(); b != nil && r.reach.Status == report.ReachComputed {
				r.reach.Symbols = b
				r.reachChanged = true
			}
		}
	}
}

// writeReach records the reach of the scan in its header.
func (r *run) writeReach(ctx context.Context) error {
	h := r.res.Scan.Header()
	if h == nil {
		return nil
	}
	reach := r.reach
	h.Scan.Reach = &reach
	return r.res.Scan.SetHeader(ctx, h)
}

// setReach sets the reach of a vulnerability finding of a scan that
// computes reach.
func (r *run) setReach(f *finding.Finding, m *model.Manifest) {
	if r.reach.Status != report.ReachComputed || f.Family != finding.FamilyVulnerability {
		return
	}
	p := packageOf(f, m)
	if p == nil {
		return
	}
	f.Reach = reachOf(r.reach.Level, p, m, f.Advisory)
}

// packageOf returns the package of a package finding in the manifest.
func packageOf(f *finding.Finding, m *model.Manifest) *model.Package {
	if f.Subject.Kind != finding.SubjectPackage || f.Subject.Package == nil {
		return nil
	}
	id, err := f.Subject.Package.PackageVersion()
	if err != nil {
		return nil
	}
	for _, p := range m.Packages {
		if p.ID.Equal(id) {
			return p
		}
	}
	return nil
}

// reachOf places a package from its code usage and the dependency graph.
// A package with no usage, such as a GitHub Action, has no reach. A level
// that a later step cannot prove is unknown, never unused.
func reachOf(level report.ReachLevel, p *model.Package, m *model.Manifest, advisory string) *finding.Reach {
	u := p.Usage
	if u == nil {
		return nil
	}
	var cause finding.ReachCause
	var fixSites []string
	if level == report.ReachFunction {
		cause = finding.ReachNoSymbolData
		if rec := recordOf(u, advisory); rec != nil {
			cause, fixSites = "", rec.FixSites
		}
	}
	if u.Imported {
		return &finding.Reach{
			Level: finding.ReachImported, Cause: cause, Confidence: finding.ConfidenceHigh,
			TestOnly: u.TestOnly, Imports: u.Imports, FixSites: fixSites,
		}
	}
	if m.Graph != nil {
		if via, from := pathFromImported(p, m); len(via) > 1 {
			return &finding.Reach{
				Level: finding.ReachImported, Cause: cause, Confidence: finding.ConfidenceMedium,
				Via: purls(via), TestOnly: from.Usage.TestOnly, FixSites: fixSites,
			}
		}
	}
	switch {
	case u.Incomplete:
		return &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachBudget, Confidence: finding.ConfidenceLow}
	case u.UnreadFiles:
		return &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachUnreadFiles, Confidence: finding.ConfidenceLow}
	case u.NoSourceFiles:
		return &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachNoSourceFiles, Confidence: finding.ConfidenceLow}
	case u.DynamicImport:
		return &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachDynamicImport, Confidence: finding.ConfidenceLow}
	case m.Graph == nil:
		return &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachNoGraph, Confidence: finding.ConfidenceLow}
	}
	return &finding.Reach{Level: finding.ReachUnused, Confidence: finding.ConfidenceMedium}
}

// recordOf returns the symbol record of an advisory of a package, or nil.
func recordOf(u *model.Usage, advisory string) *model.SymbolRecord {
	for i := range u.Symbols {
		if advisory != "" && u.Symbols[i].Advisory == advisory {
			return &u.Symbols[i]
		}
	}
	return nil
}

// pathFromImported returns the shortest dependency path from a package
// that the code imports to p, and that imported package. A path through
// a package that only tests import keeps the test mark, so a non-test
// source wins a tie.
func pathFromImported(p *model.Package, m *model.Manifest) ([]model.PackageVersion, *model.Package) {
	byKey := map[model.PackageKey]*model.Package{}
	var prod, test []model.PackageVersion
	for _, q := range m.Packages {
		if q.Usage == nil || !q.Usage.Imported {
			continue
		}
		byKey[q.ID.Key()] = q
		if q.Usage.TestOnly {
			test = append(test, q.ID)
		} else {
			prod = append(prod, q.ID)
		}
	}
	for _, from := range [][]model.PackageVersion{prod, test} {
		if path := m.Graph.PathFrom(from, p.ID); len(path) > 0 {
			return path, byKey[path[0].Key()]
		}
	}
	return nil, nil
}

func purls(path []model.PackageVersion) []string {
	out := make([]string, len(path))
	for i, id := range path {
		out[i] = id.PURL()
	}
	return out
}

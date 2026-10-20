package engine

import (
	"context"
	"errors"
	"slices"

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

// reachReport records what the call graph search of a source enricher
// read.
func (r *run) reachReport() {
	if r.reach.Status != report.ReachComputed {
		return
	}
	for _, e := range r.o.Enrichers {
		if s, ok := e.Plugin.(plugin.ReachReporter); ok {
			s.ReachReport(&r.reach)
			r.reachChanged = true
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

// reachOf places a package from its code usage and the dependency graph,
// then, at the function level, from the call path to the fix sites of the
// advisory. A package with no usage, such as a GitHub Action, has no
// reach. A level that a later step cannot prove is unknown, never unused.
func reachOf(level report.ReachLevel, p *model.Package, m *model.Manifest, advisory string) *finding.Reach {
	if p.Usage == nil {
		return nil
	}
	r := importReach(p, m)
	if level != report.ReachFunction || r.Level != finding.ReachImported {
		return r
	}
	recs := recordsOf(p.Usage, advisory)
	if len(recs) == 0 {
		r.Cause = finding.ReachNoSymbolData
		return r
	}
	rec, fr := joinRecords(recs)
	r.Symbols = &finding.ReachSymbols{Record: rec.Record, Coverage: rec.Coverage, Review: rec.Review, Source: rec.Source, License: rec.License}
	for _, x := range recs {
		for _, s := range x.FixSites {
			if !slices.Contains(r.FixSites, s) {
				r.FixSites = append(r.FixSites, s)
			}
		}
	}
	switch {
	case fr == nil:
		r.Cause = finding.ReachAnalysisFailed
	case fr.Status == model.FunctionCalled:
		r.Level, r.Confidence, r.Path, r.TestOnly = finding.ReachCalled, pathConfidence(rec, fr.Path), fr.Path, fr.TestOnly
	case fr.Status == model.FunctionNotFound:
		if r.Cause = unproven(p, m); r.Cause == "" {
			r.Level, r.Confidence = finding.ReachNotCalled, finding.ConfidenceMedium
		}
	default:
		r.Cause = finding.ReachCause(fr.Cause)
	}
	return r
}

// joinRecords joins the records of one advisory, as the entries of two
// version ranges. A call in one record is a call, and the record with the
// path names the finding. No path is no path only when each record says
// so. Else the first record that vet could not place gives the cause.
func joinRecords(recs []*model.SymbolRecord) (*model.SymbolRecord, *model.FunctionReach) {
	var unproved *model.SymbolRecord
	for _, rec := range recs {
		switch {
		case rec.Reach != nil && rec.Reach.Status == model.FunctionCalled:
			return rec, rec.Reach
		case rec.Reach == nil || rec.Reach.Status != model.FunctionNotFound:
			if unproved == nil {
				unproved = rec
			}
		}
	}
	if unproved != nil {
		return unproved, unproved.Reach
	}
	return recs[0], recs[0].Reach
}

func importReach(p *model.Package, m *model.Manifest) *finding.Reach {
	u := p.Usage
	if u.Imported {
		return &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceHigh, TestOnly: u.TestOnly, Imports: u.Imports}
	}
	if m.Graph != nil {
		if via, from := pathFromImported(p, m); len(via) > 1 {
			return &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceMedium, Via: purls(via), TestOnly: from.Usage.TestOnly}
		}
	}
	if cause := incomplete(u); cause != "" {
		return &finding.Reach{Level: finding.ReachUnknown, Cause: cause, Confidence: finding.ConfidenceLow}
	}
	if m.Graph == nil {
		return &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachNoGraph, Confidence: finding.ConfidenceLow}
	}
	return &finding.Reach{Level: finding.ReachUnused, Confidence: finding.ConfidenceMedium}
}

// incomplete names the gap of a code analysis that did not read all the
// code, or "".
func incomplete(u *model.Usage) finding.ReachCause {
	switch {
	case u.Incomplete:
		return finding.ReachBudget
	case u.UnreadFiles:
		return finding.ReachUnreadFiles
	case u.NoSourceFiles:
		return finding.ReachNoSourceFiles
	case u.DynamicImport:
		return finding.ReachDynamicImport
	}
	return ""
}

// unproven names why no call path does not prove that nothing calls the
// package, or "". The graph holds the code of the project and of the
// dependencies that vet found on the disk. Another dependency can call the
// package through code that vet did not read, so only a package that the
// project alone uses can be not called. The standard library of Go is a
// dependency of every module.
func unproven(p *model.Package, m *model.Manifest) finding.ReachCause {
	switch {
	case !p.Usage.Imported:
		return finding.ReachTransitive
	case incomplete(p.Usage) != "":
		return incomplete(p.Usage)
	case len(p.Usage.Dynamic) > 0:
		return finding.ReachDynamicFlag
	case m.Graph == nil:
		return finding.ReachNoGraph
	case p.ID.GoStdlib():
		return finding.ReachTransitive
	case reachedByOther(p, m):
		return finding.ReachTransitive
	}
	return ""
}

// mayImport reports a package other than p that the code can import: one
// that the code imports, or one with no usage, as an unchanged package of
// a pull request scan that the enricher did not read.
func mayImport(q, p *model.Package) bool {
	return !q.ID.Equal(p.ID) && (q.Usage == nil || q.Usage.Imported)
}

// pathConfidence is the lower of the confidence of the record and of the
// weakest call on the path. A maintainer verified a high record.
func pathConfidence(rec *model.SymbolRecord, path []model.PathHop) finding.Confidence {
	c := finding.ConfidenceMedium
	if rec.Verified {
		c = finding.ConfidenceHigh
	}
	for _, h := range path {
		if hc := finding.Confidence(h.Confidence); hc.Valid() && hc.Rank() < c.Rank() {
			c = hc
		}
	}
	return c
}

// reachedByOther reports another package that the code can import and
// that can call p. That is a dependency path to p, or a local package,
// such as a Cargo path dependency. A lockfile records no edge from a local
// package, and its code can be outside the target.
func reachedByOther(p *model.Package, m *model.Manifest) bool {
	var from []model.PackageVersion
	for _, q := range m.Packages {
		if !mayImport(q, p) {
			continue
		}
		if q.Local {
			return true
		}
		from = append(from, q.ID)
	}
	return len(m.Graph.PathFrom(from, p.ID)) > 0
}

// recordsOf returns the symbol records of an advisory of a package.
func recordsOf(u *model.Usage, advisory string) []*model.SymbolRecord {
	var out []*model.SymbolRecord
	for i := range u.Symbols {
		if advisory != "" && u.Symbols[i].Advisory == advisory {
			out = append(out, &u.Symbols[i])
		}
	}
	return out
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

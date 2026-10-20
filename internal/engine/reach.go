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
	rec := recordOf(p.Usage, advisory)
	if rec == nil {
		r.Cause = finding.ReachNoSymbolData
		return r
	}
	r.FixSites = rec.FixSites
	fr := rec.Reach
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
	case p.ID.Ecosystem() == model.EcosystemGo && p.ID.RawName() == "stdlib":
		return finding.ReachTransitive
	case reachedByOther(p, m):
		return finding.ReachTransitive
	}
	return ""
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

// reachedByOther reports a dependency path to p from another package that
// the code imports.
func reachedByOther(p *model.Package, m *model.Manifest) bool {
	var from []model.PackageVersion
	for _, q := range m.Packages {
		if q.Usage != nil && q.Usage.Imported && !q.ID.Equal(p.ID) {
			from = append(from, q.ID)
		}
	}
	return len(m.Graph.PathFrom(from, p.ID)) > 0
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

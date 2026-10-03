package engine

import (
	"context"
	"errors"

	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// enrich runs each enricher on the packages that lack its result, one
// batch at a time. The cache answers first. A batch that fails is recorded
// as failed, so a continued scan tries it again, and the scan goes on.
func (r *run) enrich(ctx context.Context) error {
	for _, e := range r.o.Enrichers {
		if err := r.enrichWith(ctx, e); err != nil {
			return err
		}
	}
	return r.findCapabilities(ctx)
}

// findCapabilities asks each enricher that finds capabilities, and writes
// them in place of those of an earlier run. A finder that fails adds a
// diagnostic, as a failed batch does, and the scan goes on.
func (r *run) findCapabilities(ctx context.Context) error {
	var caps []report.Capability
	for _, e := range r.o.Enrichers {
		f, ok := e.Plugin.(plugin.CapabilityFinder)
		if !ok {
			continue
		}
		cs, err := f.Capabilities(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			r.enrichError(e.Name, err)
			continue
		}
		caps = append(caps, cs...)
	}
	return r.res.Scan.ReplaceCapabilities(ctx, caps)
}

func (r *run) enrichWith(ctx context.Context, e Enricher) error {
	scan := r.res.Scan
	after, done := "", 0
	for {
		batch, err := scan.PackagesToEnrich(ctx, state.EnrichQuery{
			Enricher: e.Name, After: after, Limit: r.o.BatchSize, Introduced: r.o.BaseRef != "",
		})
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			if e.Prior && r.o.BaseRef != "" {
				return r.enrichPrior(ctx, e)
			}
			return nil
		}
		after = batch[len(batch)-1].ID.PURL()

		results, err := r.enrichBatch(ctx, e, batch)
		if err != nil {
			return err
		}
		if err := scan.SaveEnrichments(ctx, results); err != nil {
			return err
		}
		done += len(batch)
		r.o.Observer.Progress(StageEnrich, done, 0)
	}
}

func (r *run) enrichBatch(ctx context.Context, e Enricher, batch []*model.Package) ([]state.EnrichmentResult, error) {
	var todo []*model.Package
	var results []state.EnrichmentResult
	for _, p := range batch {
		// A registry has no data for a package with no version or a local
		// package, and the API rejects an empty version.
		if !p.Checkable() && !e.Local {
			results = append(results, state.EnrichmentResult{Package: p, Enricher: e.Name, Status: state.EnrichmentOK})
			continue
		}
		todo = append(todo, p)
	}
	useCache := r.o.Cache != nil && e.TTL > 0
	if useCache && !r.o.NoCacheRead && len(todo) > 0 {
		hits, misses, err := r.o.Cache.Lookup(ctx, e.Name, e.Version, todo)
		if err != nil {
			return nil, err
		}
		results, todo = append(results, hits...), misses
	}
	if len(todo) == 0 {
		return results, nil
	}

	before := make([]enrichedData, len(todo))
	for i, p := range todo {
		before[i] = dataOf(p)
	}
	status := state.EnrichmentOK
	if err := e.Plugin.Enrich(ctx, todo); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		status = state.EnrichmentFailed
		r.enrichError(e.Name, err)
	}
	fresh := make([]state.EnrichmentResult, 0, len(todo))
	for _, p := range todo {
		fresh = append(fresh, state.EnrichmentResult{Package: p, Enricher: e.Name, Status: status})
	}
	if useCache {
		own := make([]state.EnrichmentResult, len(fresh))
		for i, res := range fresh {
			own[i] = res
			own[i].Package = ownData(res.Package, before[i])
		}
		if err := r.o.Cache.Put(ctx, e.Version, e.TTL, own); err != nil {
			return nil, err
		}
	}
	return append(results, fresh...), nil
}

// enrichedData holds the data fields of a package.
type enrichedData struct {
	insight *model.Insight
	malware *model.MalwareAnalysis
	usage   *model.Usage
}

func dataOf(p *model.Package) enrichedData {
	return enrichedData{insight: p.Insight, malware: p.Malware, usage: p.Usage}
}

// ownData returns a copy of the package with only the data that the
// enricher set. The cache keeps a result for each enricher and version. A
// result must not carry the data of another enricher, or a cache hit puts
// back an old result of that enricher.
func ownData(p *model.Package, before enrichedData) *model.Package {
	out := &model.Package{ID: p.ID}
	if p.Insight != before.insight {
		out.Insight = p.Insight
	}
	if p.Malware != before.malware {
		out.Malware = p.Malware
	}
	if p.Usage != before.usage {
		out.Usage = p.Usage
	}
	return out
}

// enrichError records a failed batch. A backend that does not answer is a
// warning: the controls that need its data fail open.
func (r *run) enrichError(name string, err error) {
	if errors.Is(err, plugin.ErrUnavailable) {
		r.diags.add(report.DiagnosticWarning, CodeEnrichUnavailable, name,
			"The backend did not answer. The controls that need its data did not run on some packages.")
		return
	}
	r.diags.add(report.DiagnosticError, CodeEnrichFailed, name, err.Error())
}

// enrichPrior enriches the previous versions of the upgraded and the
// downgraded packages. The cache answers first, because the data of a
// version does not depend on the scan.
func (r *run) enrichPrior(ctx context.Context, e Enricher) error {
	todo, err := r.res.Scan.PriorToEnrich(ctx)
	if err != nil {
		return err
	}
	for len(todo) > 0 {
		n := min(len(todo), r.o.BatchSize)
		results, err := r.enrichBatch(ctx, e, todo[:n])
		if err != nil {
			return err
		}
		pkgs := make([]*model.Package, 0, len(results))
		for _, res := range results {
			pkgs = append(pkgs, res.Package)
		}
		if err := r.res.Scan.SavePrior(ctx, pkgs); err != nil {
			return err
		}
		todo = todo[n:]
	}
	return nil
}

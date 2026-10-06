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
	p, err := r.enrichProgress(ctx)
	if err != nil {
		return err
	}
	for _, e := range r.o.Enrichers {
		if err := r.enrichWith(ctx, e, p); err != nil {
			return err
		}
	}
	return r.findCapabilities(ctx)
}

// enrichProgress reports the enrich stage in packages. Each enricher
// checks each package, so the packages done are the share of the checks
// done. A continued scan starts with the checks that an earlier run saved.
type enrichProgress struct {
	obs      Observer
	packages int
	checks   int
	done     int
}

func (r *run) enrichProgress(ctx context.Context) (*enrichProgress, error) {
	p := &enrichProgress{obs: r.o.Observer}
	for _, e := range r.o.Enrichers {
		all, todo, err := r.res.Scan.EnrichCounts(ctx, state.EnrichQuery{Enricher: e.Name, Introduced: r.o.BaseRef != ""})
		if err != nil {
			return nil, err
		}
		p.packages = all
		p.checks += all
		p.done += all - todo
	}
	p.add(0)
	return p, nil
}

func (p *enrichProgress) add(checks int) {
	p.done += checks
	done := p.packages
	if p.checks > 0 {
		done = min(p.done*p.packages/p.checks, p.packages)
	}
	p.obs.Progress(StageEnrich, done, p.packages)
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

func (r *run) enrichWith(ctx context.Context, e Enricher, p *enrichProgress) error {
	scan := r.res.Scan
	after := ""
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
		after = string(batch[len(batch)-1].ID.Key())

		results, err := r.enrichBatch(ctx, e, batch)
		if err != nil {
			return err
		}
		if err := scan.SaveEnrichments(ctx, results); err != nil {
			return err
		}
		p.add(len(batch))
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

	before := make([]model.Enrichment, len(todo))
	for i, p := range todo {
		before[i] = p.Enrichment
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
		own := make([]state.EnrichmentResult, 0, len(fresh))
		for i, res := range fresh {
			// A result must not carry the data of another enricher, or a
			// cache hit puts back an old result of that enricher.
			res.Package = &model.Package{ID: res.Package.ID, Enrichment: res.Package.Since(before[i])}
			if e.SkipEmpty && res.Package.Empty() {
				continue
			}
			own = append(own, res)
		}
		if err := r.o.Cache.Put(ctx, e.Version, e.TTL, own); err != nil {
			return nil, err
		}
	}
	return append(results, fresh...), nil
}

// enrichError records a failed batch. A backend that does not answer is a
// warning: the controls that need its data fail open.
func (r *run) enrichError(name string, err error) {
	if errors.Is(err, plugin.ErrUnavailable) {
		msg := "The backend did not answer. The controls that need its data did not run on some packages."
		var u plugin.UnavailableError
		if errors.As(err, &u) {
			msg = string(u)
		}
		r.diags.add(report.DiagnosticWarning, report.CodeEnrichUnavailable, name, msg)
		return
	}
	r.diags.add(report.DiagnosticError, report.CodeEnrichFailed, name, err.Error())
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

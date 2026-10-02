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
	return nil
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
	todo := batch
	var results []state.EnrichmentResult
	useCache := r.o.Cache != nil && e.TTL > 0
	if useCache {
		hits, misses, err := r.o.Cache.Lookup(ctx, e.Name, e.Version, batch)
		if err != nil {
			return nil, err
		}
		results, todo = hits, misses
	}
	if len(todo) == 0 {
		return results, nil
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
		if err := r.o.Cache.Put(ctx, e.Version, e.TTL, fresh); err != nil {
			return nil, err
		}
	}
	return append(results, fresh...), nil
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

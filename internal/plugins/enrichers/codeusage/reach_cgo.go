//go:build cgo

package codeusage

import (
	"context"
	"errors"
	"fmt"
	iofs "io/fs"
	"maps"
	"os"
	"slices"

	"github.com/safedep/code/core"
	"github.com/safedep/code/fileindex"
	"github.com/safedep/code/fileindex/store"
	"github.com/safedep/code/fs"
	"github.com/safedep/code/plugin/indexer"
	"github.com/safedep/code/projectgraph"
	"github.com/safedep/code/projectgraph/reach"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// newReacher returns the reach search of a project. It keeps the index of
// the project, so a query indexes only its units. The store keeps the
// index of each unit, and a unit of one version never changes.
func newReacher(root string, langs []core.Language, st store.Store, project *indexer.Result) Reacher {
	return func(ctx context.Context, q ReachQuery) (ReachResult, error) {
		indexes := slices.Clone(project.Indexes)
		statuses := project.Statuses()
		units, err := indexUnits(ctx, q.Units, langs, st, &indexes, statuses)
		if err != nil {
			return ReachResult{}, err
		}
		g, err := projectgraph.Build(ctx, indexes, projectgraph.Options{
			Root: os.DirFS(root), Files: statuses, TestPaths: fileindex.DefaultTestPaths, Units: units,
		})
		if err != nil {
			return ReachResult{}, fmt.Errorf("link the call graph: %w", err)
		}
		query := reach.Query{}
		if query.Targets, err = reach.TargetsByKey(q.Targets...); err != nil {
			return ReachResult{}, err
		}
		for _, s := range q.Sources {
			src, err := sourceOf(s)
			if err != nil {
				return ReachResult{}, err
			}
			query.Sources = append(query.Sources, src)
		}
		if q.SourcesOnly {
			query.SourceMode = reach.SourcesOnly
		}
		results, err := reach.Reach(ctx, g, query)
		if err != nil {
			return ReachResult{}, entryPointError(err)
		}
		// A graph with no root of its own searches from every exported
		// function, also when the user adds sources. No path there proves
		// nothing about the code that a real caller of a library runs.
		fallback := g.Stats.RootFallback && !q.SourcesOnly
		out := ReachResult{
			Answers: make(map[string]ReachAnswer, len(results)), Roots: rootsOf(g, query),
			Versions: map[string]string{Name: Version, "projectgraph": projectgraph.Version, "reach": reach.Version},
		}
		for _, r := range results {
			out.Answers[r.Target.Key()] = answerOf(r, fallback)
			out.Stopped = out.Stopped || r.Searched.Stopped
		}
		return out, nil
	}
}

// rootsOf lists the entry points of a search: the roots of the graph and
// the sources of the query, or the sources alone.
func rootsOf(g *projectgraph.Graph, q reach.Query) *report.ReachRoots {
	var roots []projectgraph.Root
	if q.SourceMode != reach.SourcesOnly {
		roots = g.Roots
	}
	// A graph with no root of its own searches from every exported
	// function, also when the user names sources.
	out := &report.ReachRoots{Fallback: g.Stats.RootFallback && q.SourceMode != reach.SourcesOnly, Total: len(roots) + len(q.Sources)}
	if out.Fallback {
		roots = nil
	}
	for _, r := range roots[:min(len(roots), report.MaxRoots)] {
		out.List = append(out.List, report.EntryPoint{Function: r.Key, Kind: string(r.Kind), Rule: r.Rule, File: r.Site.Path, Line: r.Site.Line})
	}
	for _, s := range q.Sources[:min(len(q.Sources), report.MaxRoots-len(out.List))] {
		out.List = append(out.List, report.EntryPoint{Function: s.Key(), Kind: report.RootQuery})
	}
	return out
}

// indexUnits indexes the files of the units, adds their indexes and file
// statuses to the project ones, and returns the file system of each unit.
func indexUnits(ctx context.Context, us []Unit, langs []core.Language, st store.Store, indexes *[]*fileindex.Index, statuses map[string]fileindex.FileStatus) (map[string]iofs.FS, error) {
	if len(us) == 0 {
		return nil, nil
	}
	cfg := fs.LocalFileSystemConfig{ImportUnits: map[string]string{}}
	units := make(map[string]iofs.FS, len(us))
	for _, u := range us {
		cfg.ImportUnits[u.Dir] = u.Key
		cfg.ImportDirectories = append(cfg.ImportDirectories, u.Dir)
		// The skip patterns of a unit leave out the code that it vendors.
		cfg.ExcludePatterns = append(cfg.ExcludePatterns, fs.SkipPattern(u.Dir))
		units[u.Key] = os.DirFS(u.Dir)
	}
	slices.Sort(cfg.ImportDirectories)
	fsys, err := fs.NewLocalFileSystem(cfg)
	if err != nil {
		return nil, err
	}
	ix, err := indexer.New(indexer.Options{Languages: langs, Store: st, Imports: true})
	if err != nil {
		return nil, err
	}
	res, err := ix.Run(ctx, fsys)
	if err != nil {
		return nil, fmt.Errorf("index the dependency code: %w", err)
	}
	*indexes = append(*indexes, res.Indexes...)
	maps.Copy(statuses, res.Statuses())
	return units, nil
}

// sourceOf reads an entry point as path:function.
func sourceOf(s string) (reach.Source, error) {
	path, names, err := ParseEntrypoint(s)
	if err == nil {
		var src reach.Source
		if src, err = reach.SourceInFile(path, names...); err == nil {
			return src, nil
		}
	}
	return reach.Source{}, app.UsageError(err.Error(), "Name an entry point as cmd/app/main.go:main.")
}

// entryPointError turns an entry point that names no function into a usage
// error, so the scan exits 2. A typo must never give no path.
func entryPointError(err error) error {
	if errors.Is(err, reach.ErrUnknownSource) {
		return app.UsageError("an entry point names no function of the project: "+err.Error(),
			"Fix the entry point. vet report root list lists the entry points that vet found.")
	}
	return err
}

func answerOf(r reach.Result, rootFallback bool) ReachAnswer {
	a := ReachAnswer{Status: ReachStatus(r.Status), RootFallback: rootFallback}
	path := r.Path
	if len(path) == 0 && len(r.TestPath) > 0 {
		// Only a test reaches the target. That is still a call, so the
		// answer is found with the test mark.
		path, a.TestOnly, a.Status = r.TestPath, true, ReachFound
	}
	for _, h := range path {
		a.Path = append(a.Path, model.PathHop{
			Function: h.Key, File: h.Site.Path, Line: h.Site.Line, Root: string(h.Root),
			Edge: string(h.EdgeKind), Confidence: string(h.Confidence),
		})
	}
	for _, u := range r.Uncertainties {
		if u.Kind != reach.RootFallback {
			a.Uncertain = string(u.Kind)
			break
		}
	}
	return a
}

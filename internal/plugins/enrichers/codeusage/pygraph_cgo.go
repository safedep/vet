//go:build cgo

package codeusage

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/safedep/code/distgraph"
	"github.com/safedep/code/projectgraph/modules"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// pythonGraph builds the import graph of a Python manifest from the code
// on the disk: the Python files of the project, and the files of each
// distribution of its virtual environment. The project is the directory of
// the manifest when that directory has an environment of its own, as a
// service of a monorepo, else the scan root. It runs no Python and
// downloads nothing. A distribution whose imports vet cannot read is open.
// A graph that vet cannot trust is nil, so the manifest keeps no graph,
// and the diagnostics say why.
func (e *Enricher) pythonGraph(ctx context.Context, m *model.Manifest) (*model.Graph, error) {
	env := e.pythonEnv()
	// The environment that VIRTUAL_ENV names belongs to the whole target,
	// so only an environment under the directory of the manifest makes
	// that directory the project.
	if sub := filepath.Join(e.dir, filepath.FromSlash(path.Dir(m.Path))); sub != e.dir {
		if subEnv := e.pythonEnvAt(sub); subEnv.local {
			env = subEnv
		}
	}
	if len(env.sites) == 0 {
		e.noteGraph(fmt.Sprintf("vet builds no import graph for %s, because %s has no virtual environment. %s", m.Path, e.dir, finding.FetchHint(model.EcosystemPyPI)))
		return nil, nil
	}
	g, err := e.distributionGraphOf(ctx, env)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		e.noteGraph(fmt.Sprintf("vet builds no import graph for %s: %v", m.Path, err))
		return nil, nil
	}
	out, why := distributionGraph(g, m.Packages)
	if why != "" {
		e.noteGraph(fmt.Sprintf("vet builds no import graph for %s, because %s", m.Path, why))
		return nil, nil
	}
	if open := reachedOpenDistributions(g); len(open) > 0 {
		e.recordOpen(openModules{manifest: m.Path, dir: env.dir, ecosystem: model.EcosystemPyPI, modules: open})
	}
	return out, nil
}

// pythonGraphResult is the distribution graph of one environment, built
// once for the scan. Each Python manifest of the directory reads it.
type pythonGraphResult struct {
	g   *distgraph.Graph
	err error
}

// distributionGraphOf builds the distribution graph of an environment once.
// The graph does not depend on the manifest, and a target can hold a
// requirements.txt, a pyproject.toml and a lockfile for one environment.
func (e *Enricher) distributionGraphOf(ctx context.Context, env *pythonEnvironment) (*distgraph.Graph, error) {
	e.pyMu.Lock()
	cached, ok := e.pyGraphs[env.dir]
	e.pyMu.Unlock()
	if ok {
		r := cached.(pythonGraphResult)
		return r.g, r.err
	}
	in := distgraph.Input{ProjectFS: os.DirFS(env.dir)}
	for _, s := range env.sites {
		in.SitePackages = append(in.SitePackages, os.DirFS(s.dir))
	}
	start := time.Now()
	g, err := distgraph.Build(ctx, in)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil {
		for _, p := range g.Problems {
			log.Debugf("codeusage: import graph of %s: %s: %s", env.dir, p.Path, p.Text)
		}
		log.Debugf("codeusage: import graph of %s: %d distributions, %d files in %s",
			env.dir, g.Stats.Distributions, g.Stats.Files, time.Since(start).Round(time.Millisecond))
	}
	e.pyMu.Lock()
	defer e.pyMu.Unlock()
	if e.pyGraphs == nil {
		e.pyGraphs = map[string]any{}
	}
	e.pyGraphs[env.dir] = pythonGraphResult{g: g, err: err}
	return g, err
}

// distributionGraph converts the distribution graph into a graph of imports
// of the manifest. A distribution of the environment is the package with
// its name. A manifest can list one name at two versions, as a lockfile
// does with an environment marker, and the version that the environment
// holds is the package. The other versions are not installed. A
// distribution that the manifest does not list, as a dependency of a
// dependency that requirements.txt leaves out, is no package of the
// manifest. So it passes its edges on: an edge into it becomes an edge to
// each package that it imports. A package of the manifest that is not
// installed has no imports that vet can read, so it is open. It returns
// the graph and "", or nil and why vet cannot trust the graph: the
// environment holds another version of a package that the code reaches,
// or the project can import any distribution.
func distributionGraph(g *distgraph.Graph, pkgs []*model.Package) (*model.Graph, string) {
	listed := map[string][]model.PackageVersion{}
	for _, p := range pkgs {
		if p.ID.Ecosystem() == model.EcosystemPyPI {
			listed[p.ID.Name()] = append(listed[p.ID.Name()], p.ID)
		}
	}
	byName := map[string]model.PackageVersion{}
	var notInstalled []model.PackageVersion
	for name, ids := range listed {
		byName[name] = ids[0]
		if n, ok := g.Node(name); ok {
			if installed, err := model.NewPackageVersion(model.EcosystemPyPI, n.Distribution.Name, n.Distribution.Version); err == nil {
				if i := slices.IndexFunc(ids, installed.Equal); i >= 0 {
					byName[name] = ids[i]
				}
			}
		}
		for _, id := range ids {
			if !id.Equal(byName[name]) {
				notInstalled = append(notInstalled, id)
			}
		}
	}
	open := map[string]bool{}
	for _, n := range g.Nodes {
		name := modules.NormalizePythonName(n.Distribution.Name)
		open[name] = n.Open() || !n.Walked
		id, mapped := byName[name]
		if !mapped || !n.Reached || id.Version() == "" {
			continue
		}
		if installed, err := model.NewPackageVersion(model.EcosystemPyPI, n.Distribution.Name, n.Distribution.Version); err != nil || !installed.Equal(id) {
			return nil, fmt.Sprintf("the environment holds %s %s, and the manifest %s", n.Distribution.Name, n.Distribution.Version, id.RawVersion())
		}
	}
	mainKey := modules.NormalizePythonName(g.Main.Name)
	if open[mainKey] {
		n, _ := g.Node(g.Main.Name)
		return nil, "the project can import any distribution: " + n.Reason
	}
	next := map[string][]string{}
	var mainProd []string
	for _, edge := range g.Edges {
		if edge.Kind != distgraph.StateImports || edge.To.Name == distgraph.StdName {
			continue
		}
		from, to := modules.NormalizePythonName(edge.From.Name), modules.NormalizePythonName(edge.To.Name)
		next[from] = append(next[from], to)
		if from == mainKey && !edge.TestOnly {
			mainProd = append(mainProd, to)
		}
	}
	// A root that no edge from the non-test files of the project leads to
	// is a test root.
	prodNext := maps.Clone(next)
	prodNext[mainKey] = mainProd
	prod, _ := passOn(mainKey, prodNext, byName, open)

	out := model.NewGraph()
	out.SetImports()
	for _, id := range notInstalled {
		out.MarkOpen(id)
	}
	for _, from := range append([]string{mainKey}, slices.Sorted(maps.Keys(byName))...) {
		targets, hiddenOpen := passOn(from, next, byName, open)
		if from == mainKey {
			if hiddenOpen != "" {
				return nil, fmt.Sprintf("the project imports %s, which vet cannot read", hiddenOpen)
			}
			for _, t := range targets {
				if slices.ContainsFunc(prod, t.Equal) {
					out.AddRoot(t)
				} else {
					out.AddTestRoot(t)
				}
			}
			continue
		}
		id := byName[from]
		if _, installed := g.Node(from); !installed || open[from] || hiddenOpen != "" {
			out.MarkOpen(id)
		}
		for _, t := range targets {
			out.AddEdge(id, t)
		}
	}
	return out, ""
}

// reachedOpenDistributions returns the open distributions that the project
// reaches, sorted by name.
func reachedOpenDistributions(g *distgraph.Graph) []string {
	var out []string
	for _, n := range g.Nodes {
		if n.Open() && n.Reached && n.Distribution.Name != g.Main.Name {
			out = append(out, n.Distribution.Name)
		}
	}
	return out
}

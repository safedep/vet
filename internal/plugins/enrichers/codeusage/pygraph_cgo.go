//go:build cgo

package codeusage

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/safedep/code/distgraph"
	"github.com/safedep/code/projectgraph/modules"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// pythonGraph builds the import graph of a Python manifest from the code
// on the disk: the Python files of the target, and the files of each
// distribution of the virtual environment of the target. It runs no
// Python and downloads nothing. A distribution whose imports vet cannot
// read is open. A graph that vet cannot trust is nil, so the manifest
// keeps no graph, and the diagnostics say why.
func (e *Enricher) pythonGraph(ctx context.Context, m *model.Manifest) (*model.Graph, error) {
	env := e.pythonEnv()
	if len(env.sites) == 0 {
		e.noteGraph(fmt.Sprintf("vet builds no import graph for %s, because the target has no virtual environment. %s", m.Path, finding.FetchHint(model.EcosystemPyPI)))
		return nil, nil
	}
	in := distgraph.Input{ProjectFS: os.DirFS(e.dir)}
	for _, s := range env.sites {
		in.SitePackages = append(in.SitePackages, os.DirFS(s.dir))
	}
	start := time.Now()
	g, err := distgraph.Build(ctx, in)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		e.noteGraph(fmt.Sprintf("vet builds no import graph for %s: %v", m.Path, err))
		return nil, nil
	}
	for _, p := range g.Problems {
		log.Debugf("codeusage: import graph of %s: %s: %s", m.Path, p.Path, p.Text)
	}
	log.Debugf("codeusage: import graph of %s: %d distributions, %d files in %s",
		m.Path, g.Stats.Distributions, g.Stats.Files, time.Since(start).Round(time.Millisecond))
	out, why := distributionGraph(g, m.Packages)
	if why != "" {
		e.noteGraph(fmt.Sprintf("vet builds no import graph for %s, because %s", m.Path, why))
		return nil, nil
	}
	if open := reachedOpenDistributions(g); len(open) > 0 {
		e.recordOpen(openModules{manifest: m.Path, dir: m.Path, ecosystem: model.EcosystemPyPI, modules: open})
	}
	return out, nil
}

// distributionGraph converts the distribution graph into a graph of imports
// of the manifest. A distribution of the environment is the package with
// its name. A distribution that the manifest does not list, as a
// dependency of a dependency that requirements.txt leaves out, is no
// package of the manifest. So it passes its edges on: an edge into it
// becomes an edge to each package that it imports. A package of the
// manifest that is not installed has no imports that vet can read, so it
// is open. It returns the graph and "", or nil and why vet cannot trust
// the graph: the environment holds another version of a package that the
// code reaches, or the project can import any distribution.
func distributionGraph(g *distgraph.Graph, pkgs []*model.Package) (*model.Graph, string) {
	byName := map[string]model.PackageVersion{}
	for _, p := range pkgs {
		if p.ID.Ecosystem() == model.EcosystemPyPI {
			byName[p.ID.Name()] = p.ID
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
		if installed, err := model.NewPackageVersion(model.EcosystemPyPI, n.Distribution.Name, n.Distribution.Version); err == nil && !installed.Equal(id) {
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

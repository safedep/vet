package codeusage

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/safedep/code/fileindex/store/localdbstore"
	"github.com/safedep/code/modgraph"
	"github.com/safedep/dry/log"
	"golang.org/x/mod/modfile"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// CodeModuleGraph is the diagnostic code of a manifest whose graph of
// imports is missing or has packages whose imports vet cannot read: a Go
// module with no source on the disk, or an open Python distribution.
const CodeModuleGraph = "module_graph"

// Graph builds the graph of imports of a manifest from the code on the
// disk: the module graph of a go.mod, or the import graph of a Python
// manifest with a virtual environment. It runs no build and downloads
// nothing. A graph that vet cannot trust is nil, so the manifest keeps no
// graph, and the diagnostics say why.
func (e *Enricher) Graph(ctx context.Context, m *model.Manifest) (*model.Graph, error) {
	switch {
	case e.dir == "":
		return nil, nil
	case m.Ecosystem == model.EcosystemGo:
		return e.goGraph(ctx, m)
	case m.Ecosystem == model.EcosystemPyPI:
		return e.pythonGraph(ctx, m)
	}
	return nil, nil
}

// goGraph builds the module graph of a go.mod: the code of the main
// module, and of each module of the build list in the vendor directory, in
// a local replacement inside the scan root or in the module cache. A module
// with no source is open, because vet does not know what it imports.
func (e *Enricher) goGraph(ctx context.Context, m *model.Manifest) (*model.Graph, error) {
	modDir, ok := moduleDirOf(m.Path)
	if !ok {
		return nil, nil
	}
	dir := filepath.Join(e.dir, filepath.FromSlash(modDir))
	work, err := workspaceOf(e.dir, dir)
	if err != nil {
		e.noteGraph(fmt.Sprintf("vet builds no module graph for %s, because %v", m.Path, err))
		return nil, nil
	}
	required, err := requiredModules(dir)
	if err != nil {
		e.noteGraph(fmt.Sprintf("vet builds no module graph for %s: %v", m.Path, err))
		return nil, nil
	}
	start := time.Now()
	sources, err := modgraph.Discover(modgraph.DiscoverOptions{Dir: dir, Work: work, ModuleCache: goModCache(), LocalRoot: e.dir})
	if err != nil {
		e.noteGraph(fmt.Sprintf("vet builds no module graph for %s: %v", m.Path, err))
		return nil, nil
	}
	in := modgraph.Input{MainFS: newListedFS(os.DirFS(dir)), Modules: e.listed(sources)}
	if st := e.moduleCache(ctx); st != nil {
		in.Store = st
		defer st.Flush(ctx)
	}
	g, err := modgraph.Build(ctx, in)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.Is(err, modgraph.ErrUnpruned):
		e.noteGraph(fmt.Sprintf("vet builds no module graph for %s, because its go directive is below 1.17, so it can leave out modules of the build", m.Path))
		return nil, nil
	case err != nil:
		e.noteGraph(fmt.Sprintf("vet builds no module graph for %s: %v", m.Path, err))
		return nil, nil
	}
	log.Debugf("codeusage: module graph of %s: %d modules, %d files, %d packages in %s",
		m.Path, len(g.Nodes), g.Stats.Files, g.Stats.Packages, time.Since(start).Round(time.Millisecond))
	out, why := moduleGraph(g, m.Packages, localReplacements(sources), required)
	if why != "" {
		e.noteGraph(fmt.Sprintf("vet builds no module graph for %s, because %s", m.Path, why))
		return nil, nil
	}
	if open := reachedOpen(g); len(open) > 0 {
		e.recordOpen(openModules{manifest: m.Path, dir: modDir, ecosystem: model.EcosystemGo, modules: open})
	}
	return out, nil
}

// recordOpen keeps the open packages that a graph reaches, for the
// diagnostics. go.mod and vendor/modules.txt of one module get the same
// graph, and the Python manifests of one directory get the same graph, so
// the open packages count once for each directory of an ecosystem.
func (e *Enricher) recordOpen(o openModules) {
	e.graphMu.Lock()
	defer e.graphMu.Unlock()
	if !slices.ContainsFunc(e.graphOpen, func(have openModules) bool { return have.ecosystem == o.ecosystem && have.dir == o.dir }) {
		e.graphOpen = append(e.graphOpen, o)
	}
}

// moduleDirOf returns the directory of the module of a Go manifest: the
// directory of a go.mod, or the directory above vendor/modules.txt. The
// vendor list holds the modules of that go.mod, so both get its graph.
func moduleDirOf(manifest string) (string, bool) {
	switch dir := path.Dir(manifest); {
	case path.Base(manifest) == "go.mod":
		return dir, true
	case path.Base(manifest) == "modules.txt" && path.Base(dir) == "vendor":
		return path.Dir(dir), true
	}
	return "", false
}

// listed gives each source a file system that keeps its directory
// listings. A source that never changes, as a directory of the module
// cache, shares one for the whole scan, so the go.mod files of a target
// that use one module version list its directories once.
// The listings stay in memory for the scan.
func (e *Enricher) listed(sources []modgraph.Source) []modgraph.Source {
	out := slices.Clone(sources)
	e.graphMu.Lock()
	defer e.graphMu.Unlock()
	for i, s := range out {
		if s.FS == nil {
			continue
		}
		if !s.Immutable {
			out[i].FS = newListedFS(s.FS)
			continue
		}
		key := cmp.Or(s.Origin, s.Module).String()
		if e.listings == nil {
			e.listings = map[string]*listedFS{}
		}
		if e.listings[key] == nil {
			e.listings[key] = newListedFS(s.FS)
		}
		out[i].FS = e.listings[key]
	}
	return out
}

// moduleCache returns the module graph cache in cache.db, or nil when the
// scan has no cache.db or vet cannot open it.
func (e *Enricher) moduleCache(ctx context.Context) *moduleStore {
	e.graphCacheOnce.Do(func() {
		if e.o.Cache == nil {
			return
		}
		st, err := localdbstore.New(ctx, e.o.Cache)
		if err != nil {
			log.Warnf("module graph cache: %v. vet reads each module", err)
			return
		}
		e.graphCache = newModuleStore(st)
	})
	return e.graphCache
}

// moduleGraph converts the module graph into a graph of imports of the
// manifest. A module of the build list is the package with its path, or the
// package that replaces it. A module that go.mod does not require, as a
// local replacement, another module of a workspace or a module that only
// the workspace adds, is no package of the manifest. So it passes its edges
// on: an edge into it becomes an edge to each package that it imports. It
// returns the graph and "", or nil and why vet cannot trust the graph. A
// module that Build did not walk is open, because its edges are not known.
func moduleGraph(g *modgraph.Graph, pkgs []*model.Package, local, required map[string]bool) (*model.Graph, string) {
	byPath := map[string]model.PackageVersion{}
	for _, p := range pkgs {
		if p.ID.Ecosystem() == model.EcosystemGo && !p.ID.GoStdlib() {
			byPath[cmp.Or(p.Replaces, p.ID.RawName())] = p.ID
		}
	}
	open := map[string]bool{}
	for _, n := range g.Nodes {
		open[n.Module.Path] = n.Open() || !n.Walked
		_, mapped := byPath[n.Module.Path]
		// A reached module that go.mod requires and that maps to no package
		// shows a gap in the mapping, so its finding would read the graph of
		// another package.
		if n.Reached && !mapped && required[n.Module.Path] && !local[n.Module.Path] {
			return nil, fmt.Sprintf("the module %s is no package of the manifest", n.Module)
		}
	}
	// A package with no module in the build list has no edges, so it would
	// read unused. A vendor list that go mod vendor did not refresh holds
	// such a package.
	for _, path := range slices.Sorted(maps.Keys(byPath)) {
		if _, ok := g.Node(path); !ok {
			return nil, fmt.Sprintf("the package %s is no module of the build list", byPath[path])
		}
	}
	if open[g.Main.Path] {
		n, _ := g.Node(g.Main.Path)
		return nil, "the main module can import any module: " + n.Reason
	}
	next := map[string][]string{}
	var mainProd []string
	for _, e := range g.Edges {
		if e.Kind == modgraph.StateImports && e.To.Path != modgraph.StdPath {
			next[e.From.Path] = append(next[e.From.Path], e.To.Path)
			if e.From.Path == g.Main.Path && !e.TestOnly {
				mainProd = append(mainProd, e.To.Path)
			}
		}
	}
	// A root that no edge from the non-test files of the main module leads
	// to is a test root. The walk of all edges already rejects a hidden open
	// module, so this walk ignores it.
	prodNext := maps.Clone(next)
	prodNext[g.Main.Path] = mainProd
	prod, _ := passOn(g.Main.Path, prodNext, byPath, open)

	out := model.NewGraph()
	out.SetImports()
	for _, from := range append([]string{g.Main.Path}, slices.Sorted(maps.Keys(byPath))...) {
		targets, hiddenOpen := passOn(from, next, byPath, open)
		if from == g.Main.Path {
			if hiddenOpen != "" {
				return nil, fmt.Sprintf("the main module imports %s, which vet cannot read", hiddenOpen)
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
		id := byPath[from]
		if open[from] || hiddenOpen != "" {
			out.MarkOpen(id)
		}
		for _, t := range targets {
			out.AddEdge(id, t)
		}
	}
	return out, ""
}

// passOn returns the packages that a module imports, through the nodes that
// are no package of the manifest, and the first such node that is open.
func passOn(from string, next map[string][]string, byPath map[string]model.PackageVersion, open map[string]bool) ([]model.PackageVersion, string) {
	var out []model.PackageVersion
	hiddenOpen := ""
	seen := map[string]bool{from: true}
	queue := slices.Clone(next[from])
	for len(queue) > 0 {
		to := queue[0]
		queue = queue[1:]
		if seen[to] {
			continue
		}
		seen[to] = true
		if id, ok := byPath[to]; ok {
			out = append(out, id)
			continue
		}
		if open[to] && hiddenOpen == "" {
			hiddenOpen = to
		}
		queue = append(queue, next[to]...)
	}
	return out, hiddenOpen
}

// localReplacements returns the modules of the build list that a replace
// directive replaces with a directory.
func localReplacements(sources []modgraph.Source) map[string]bool {
	out := map[string]bool{}
	for _, s := range sources {
		if s.Origin.Path != "" && s.Origin.Version == "" {
			out[s.Module.Path] = true
		}
	}
	return out
}

// reachedOpen returns the open modules that the build reaches, sorted. An
// open module that nothing reaches changes no reach result.
func reachedOpen(g *modgraph.Graph) []string {
	var out []string
	for _, n := range g.Nodes {
		if n.Open() && n.Reached {
			out = append(out, n.Module.Path)
		}
	}
	return out
}

// workspaceOf returns the go.work file whose use directives name the module
// directory, or "". The go command reads the go.work that GOWORK names, or
// else the first go.work of the module directory and its parents, inside
// or above the scan root. It builds each module that the workspace uses with
// the build list of the workspace. A go.work that vet cannot read or parse
// counts as one that uses the module, so Discover fails on it and the
// manifest keeps no graph. The go command refuses a relative GOWORK, so no
// build exists.
func workspaceOf(root, dir string) (string, error) {
	switch work := os.Getenv("GOWORK"); work {
	case "off":
		return "", nil
	case "", "auto":
	default:
		if !filepath.IsAbs(work) {
			return "", fmt.Errorf("GOWORK=%s is not an absolute path, so the go command builds nothing", work)
		}
		if data, err := os.ReadFile(work); err == nil && !usesModule(data, filepath.Dir(work), dir) {
			return "", nil
		}
		return work, nil
	}
	for d := dir; ; d = filepath.Dir(d) {
		name := filepath.Join(d, "go.work")
		if data, err := os.ReadFile(name); err == nil {
			if !usesModule(data, d, dir) {
				return "", nil
			}
			return name, nil
		}
		if filepath.Dir(d) == d {
			return "", nil
		}
	}
}

// requiredModules returns the modules that the go.mod in dir requires.
func requiredModules(dir string) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, err
	}
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range f.Require {
		out[r.Mod.Path] = true
	}
	return out, nil
}

func usesModule(data []byte, workDir, dir string) bool {
	f, err := modfile.ParseWork("go.work", data, nil)
	if err != nil {
		return true
	}
	for _, u := range f.Use {
		p := filepath.FromSlash(u.Path)
		if !filepath.IsAbs(p) {
			p = filepath.Join(workDir, p)
		}
		if samePath(p, dir) {
			return true
		}
	}
	return false
}

// samePath compares two paths after it resolves their links. The scan root
// is canonical, but GOWORK and a use directive can name a link to it.
func samePath(a, b string) bool {
	resolve := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return filepath.Clean(p)
	}
	return resolve(a) == resolve(b)
}

// openModules are the open packages that the graph of a manifest reaches:
// the modules of a go.mod with no source, or the distributions of a Python
// manifest whose imports vet cannot read.
type openModules struct {
	manifest  string
	dir       string
	ecosystem model.Ecosystem
	modules   []string
}

// graphDiagnostics reports each manifest with no graph, and one diagnostic
// per ecosystem for the open packages of all its graphs.
func (e *Enricher) graphDiagnostics() []report.Diagnostic {
	e.graphMu.Lock()
	defer e.graphMu.Unlock()
	out := slices.Clone(e.graphNotes)
	for _, eco := range []model.Ecosystem{model.EcosystemGo, model.EcosystemPyPI} {
		var graphs []openModules
		count := 0
		for _, o := range e.graphOpen {
			if o.ecosystem == eco {
				graphs = append(graphs, o)
				count += len(o.modules)
			}
		}
		if count == 0 {
			continue
		}
		first := graphs[0]
		nouns := dependencyNouns[eco]
		noun := nouns[1]
		if count == 1 {
			noun = nouns[0]
		}
		where := first.manifest
		if len(graphs) > 1 {
			where = fmt.Sprintf("%d %s files", len(graphs), path.Base(first.manifest))
			if eco == model.EcosystemPyPI {
				where = fmt.Sprintf("%d manifests", len(graphs))
			}
		}
		out = append(out, report.Diagnostic{
			Level: report.DiagnosticWarning, Code: CodeModuleGraph, Component: Name, Count: count,
			Message: fmt.Sprintf("vet cannot read the imports of %d %s of %s, such as %s of %s, so reach can be unknown for the packages that they can import. %s",
				count, noun, where, first.modules[0], first.manifest, openAdvice[eco]),
		})
	}
	return out
}

// openAdvice says what a person can do about an open package of an
// ecosystem. A Go module is open when its source is not on the disk. A
// Python distribution is open when it has an extension module, imports a
// computed name, or imports a module that no distribution holds, and no
// install changes that.
var openAdvice = map[model.Ecosystem]string{
	model.EcosystemGo:   finding.FetchHint(model.EcosystemGo),
	model.EcosystemPyPI: "An extension module, an import of a computed name or an import of a module that no distribution holds hides the imports of a distribution.",
}

func (e *Enricher) noteGraph(msg string) {
	log.Debugf("codeusage: %s", msg)
	e.graphMu.Lock()
	defer e.graphMu.Unlock()
	e.graphNotes = append(e.graphNotes, report.Diagnostic{
		Level: report.DiagnosticWarning, Code: CodeModuleGraph, Component: Name, Message: msg,
	})
}

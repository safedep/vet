// Package codeusage is the enricher of code usage evidence and of the
// xBOM (decisions P8). It reads the source files of the target once. It
// finds the imports and sets model.Package.Usage: whether the code imports
// the package, and in which files. The engine adds the usage to each
// package finding as evidence. It also matches the code signatures on the
// call graph of each file, and each signature that matches is a capability
// of the application, such as a call to an LLM provider.
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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/safedep/code/fileindex"
	"github.com/safedep/code/fileindex/store/localdbstore"
	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/pathglob"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/symbols"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the registered name of the enricher and the config key under
// plugins. It is on by default for a directory target on a build with
// CGO. plugins.codeusage.enabled: false turns it off.
const Name = "codeusage"

// Version changes when the mapping or the signatures change.
const Version = "14"

// maxFiles bounds the files that a package usage lists.
const maxFiles = 20

// maxSites bounds the calls and the dynamic sites of a package usage.
const maxSites = 200

// Evidence is one import of a module in a source file.
type Evidence struct {
	// PackageHint is the package that holds the module, as the analysis
	// guesses it, for example "yaml" for "import yaml".
	PackageHint string
	ModuleName  string
	// Language is the language of the file, as safedep/code names it.
	Language string
	FilePath string
	Line     uint
}

// Signature describes a code signature: what a match of it means.
type Signature struct {
	ID          string
	Description string
	Vendor      string
	Product     string
	Service     string
	Tags        []string
}

// Match is one call in a source file that matches a code signature.
type Match struct {
	Signature Signature
	FilePath  string
	Line      int
	Column    int
	Language  string
	// Callee is the called function, as the call graph resolves it.
	Callee string
}

// ExternalCall is one call of a source file into an imported module.
// Module is the import that the call target starts with.
type ExternalCall struct {
	FilePath string
	Line     int
	Language string
	Callee   string
	Module   string
}

// FileFailure is a source file that the analysis could not read, parse
// or analyze. The rest of the scan goes on without it.
type FileFailure struct {
	FilePath string
	// Stage is read, parse or the name of the analysis that failed.
	Stage string
	Err   string
}

// Analysis is what the analyzer finds in the source files under a
// directory.
type Analysis struct {
	Usage   []Evidence
	Matches []Match
	Failed  []FileFailure
	// Files holds the index status of each source file by name: indexed,
	// cached, missing, failed or truncated.
	Files map[string]fileindex.FileStatus
	// DynamicImports holds the languages of the files that import a module
	// by a computed name.
	DynamicImports map[string]bool
	Calls          []ExternalCall
	Dynamic        []model.DynamicSite
	// Languages holds the languages of the source files that the analysis
	// found, and Unread the languages of a file that it could not read,
	// parse or index whole.
	Languages map[string]bool
	Unread    map[string]bool
	// Reach searches the call graph of the project and of the dependency
	// units. It is nil in a build with no code analysis.
	Reach Reacher
}

// Unit is the source of one dependency, with its unit key. A key names the
// language, the name and the version, as cargo:time@0.3.30.
type Unit struct {
	Key string
	// Dir is the directory of the code of the unit.
	Dir string
	// Root is the directory that the paths of the unit are relative to,
	// when it is not Dir: a site-packages directory holds the package
	// directories of a Python distribution, and Python imports them by
	// their path under it.
	Root string
	// Dirs are the other directories of the code of the unit under Root,
	// as the packages of a namespace package.
	Dirs []string
}

// ReachQuery asks whether the code calls the target keys. Sources are the
// entry points that the user names, as path:function. SourcesOnly starts
// the search from them alone.
type ReachQuery struct {
	Units       []Unit
	Targets     []string
	Sources     []string
	SourcesOnly bool
}

// ReachAnswer is the answer for one target key.
type ReachAnswer struct {
	Status ReachStatus
	Path   []model.PathHop
	// TestOnly marks an answer whose only path starts at a test.
	TestOnly bool
	// Uncertain names the kind of the first uncertainty, as
	// unresolved-call.
	Uncertain string
	// RootFallback marks a graph with no entry point, where every exported
	// function is a root.
	RootFallback bool
}

// ReachResult is the answer of a reach query for each target key, the
// entry points of the search and the versions of the call graph.
type ReachResult struct {
	Answers  map[string]ReachAnswer
	Roots    *report.ReachRoots
	Versions map[string]string
	// Stopped marks a search that its budget stopped.
	Stopped bool
}

// Reacher runs one reach query.
type Reacher func(ctx context.Context, q ReachQuery) (ReachResult, error)

// ReachKey is the config key of the reach level.
const ReachKey = "plugins." + Name + ".options.reach"

// DefaultBudget bounds the code analysis when plugins.codeusage.options
// sets no budget.
const DefaultBudget = 5 * time.Minute

// Settings are plugins.codeusage.options.
type Settings struct {
	// Reach is the reach level of the vulnerability findings: off, import
	// or function. The default is import. --reach overrides it.
	Reach string `json:"reach,omitempty" jsonschema:"enum=off,enum=import,enum=function"`
	// Budget bounds the time of the code analysis, as 90s or 10m. The
	// default is 5m.
	Budget string `json:"budget,omitempty"`
	// SymbolsUpdate asks the host of the symbol data for a newer bundle,
	// at most once a day. The default is true.
	SymbolsUpdate *bool `json:"symbols_update,omitempty"`
	// SymbolsBundle reads the symbol data from a directory with a copy of
	// the host files, for a machine with no network.
	SymbolsBundle string `json:"symbols_bundle,omitempty"`
	// SymbolsPin keeps the scan on one bundle id, for a reproducible run.
	SymbolsPin string `json:"symbols_pin,omitempty"`
	// Entrypoints are entry points that vet does not find itself, as
	// cmd/app/main.go:main. --entrypoint adds to the list.
	Entrypoints []string `json:"entrypoints,omitempty"`
	// EntrypointsOnly starts the call graph search from Entrypoints alone.
	EntrypointsOnly bool `json:"entrypoints_only,omitempty"`
}

// Config is plugins.codeusage.options with its defaults.
type Config struct {
	Reach           report.ReachLevel
	Budget          time.Duration
	SymbolsUpdate   bool
	SymbolsBundle   string
	SymbolsPin      string
	Entrypoints     []string
	EntrypointsOnly bool
}

// ParseSettings reads plugins.codeusage.options.
func ParseSettings(cfg plugin.Config) (Config, error) {
	var s Settings
	if err := cfg.Decode(&s); err != nil {
		return Config{}, err
	}
	level, err := report.ParseReachLevel(s.Reach)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", Name, err)
	}
	c := Config{
		Reach: level, Budget: DefaultBudget, SymbolsUpdate: s.SymbolsUpdate == nil || *s.SymbolsUpdate,
		SymbolsBundle: s.SymbolsBundle, SymbolsPin: s.SymbolsPin, Entrypoints: s.Entrypoints, EntrypointsOnly: s.EntrypointsOnly,
	}
	for _, ep := range s.Entrypoints {
		if _, _, err := ParseEntrypoint(ep); err != nil {
			return Config{}, fmt.Errorf("%s: entrypoints: %w", Name, err)
		}
	}
	if s.Budget != "" {
		if c.Budget, err = time.ParseDuration(s.Budget); err != nil || c.Budget <= 0 {
			return Config{}, fmt.Errorf("%s: budget %q is not a positive duration such as 90s or 10m", Name, s.Budget)
		}
	}
	return c, nil
}

// ParseEntrypoint reads an entry point as path:function, as
// cmd/app/main.go:main or app/server.py:Router.handle. The path is
// relative to the target.
func ParseEntrypoint(s string) (file string, names []string, err error) {
	var fn string
	var ok bool
	file, fn, ok = strings.Cut(s, ":")
	file = path.Clean(filepath.ToSlash(file))
	if !ok || file == "." || fn == "" || slices.Contains(strings.Split(fn, "."), "") {
		return "", nil, fmt.Errorf("entry point %q is not path:function, as cmd/app/main.go:main", s)
	}
	if path.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../") {
		return "", nil, fmt.Errorf("entry point %q is not a path in the target", s)
	}
	return file, strings.Split(fn, "."), nil
}

// EntrypointsKey is the config key of the entry points that the user names.
const EntrypointsKey = "plugins." + Name + ".options.entrypoints"

// EntrypointsOnlyKey is the config key that limits the call graph search to
// the entry points that the user names.
const EntrypointsOnlyKey = "plugins." + Name + ".options.entrypoints_only"

// OptionsSchema returns the JSON Schema of the options.
func OptionsSchema() []byte { return optschema.Of(&Settings{}) }

// indexRetention is how long the code index keeps a file that no scan
// reads. The key of an index holds the content hash of the file, so an
// index never goes stale. Only disk space bounds it.
const indexRetention = 30 * 24 * time.Hour

// PruneIndex deletes the index of each file that no scan read in
// indexRetention before now, and returns how many rows it deleted.
func PruneIndex(ctx context.Context, cache localdb.Manager, now time.Time) (int, error) {
	st, err := localdbstore.New(ctx, cache)
	if err != nil {
		return 0, err
	}
	return st.Prune(ctx, now.Add(-indexRetention))
}

// Analyzer analyzes the source files under a directory. When ctx is done,
// it returns the analysis so far with the error of ctx.
type Analyzer func(ctx context.Context, dir string) (Analysis, error)

// Options are the options of the enricher.
type Options struct {
	// BaseRef is the base ref of pull request mode. Each capability then
	// gets the change against the base commit.
	BaseRef string
	// Cache is the manager of cache.db. The analysis keeps the index of
	// each file there. A nil Cache parses every file on each scan.
	Cache localdb.Manager
	// Budget bounds the time of the analysis. The files that it does not
	// reach are missing, and the scan goes on without them. Zero means no
	// bound.
	Budget time.Duration
	// Symbols finds the vulnerable functions of the vulnerabilities of Go,
	// Rust and Python packages. A nil Symbols finds none, and the enricher then
	// searches no call path.
	Symbols symbols.Source
	// Entrypoints are the entry points that the user names, as
	// cmd/app/main.go:main. The search starts from them and from the
	// entry points that vet finds.
	Entrypoints []string
	// EntrypointsOnly starts the search from Entrypoints alone.
	EntrypointsOnly bool
}

// Enricher sets model.Package.Usage from the imports of the target, and
// finds the capabilities of the target.
type Enricher struct {
	dir     string
	o       Options
	analyze Analyzer

	once    sync.Once
	modules map[module]map[string]int
	matches []Match
	failed  []FileFailure
	stopped bool
	missing int
	// dynamic holds the languages with an import by a computed name.
	dynamic map[string]bool
	// symbols is the symbol source once the scan has code that it covers.
	symbols   symbols.Source
	languages map[string]bool
	unread    map[string]bool
	calls     []ExternalCall
	reach     Reacher
	// reachStopped and reachErr record a call graph search that did not
	// finish.
	reachStopped bool
	reachErr     error
	roots        *report.ReachRoots
	versions     map[string]string
	searched     bool
	// sources counts the packages with a record whose code vet found.
	// noCode holds the names of those whose code it did not find, by
	// ecosystem.
	sources int
	noCode  map[model.Ecosystem][]string
	sites   []model.DynamicSite
	// hints holds the package hint of each imported module, by language
	// and name, for the calls that name the module only.
	hints    map[module]string
	own      []string
	provider provider
	err      error

	// graphNotes are the go.mod files with no module graph, and graphOpen
	// the open modules of the module graphs.
	graphMu    sync.Mutex
	graphNotes []report.Diagnostic
	graphOpen  []openModules
	// listings are the file systems of the module sources that never
	// change, by module version.
	listings map[string]*listedFS
	// graphCache keeps the module graph cache in cache.db, or is nil.
	graphCacheOnce sync.Once
	graphCache     *moduleStore
	// pyEnvs are the Python environments of the target, by directory: the
	// scan root, and the directory of a manifest with an environment of
	// its own. pyGraphs are the distribution graphs of those directories,
	// which only a build with CGO sets.
	pyMu     sync.Mutex
	pyEnvs   map[string]*pythonEnvironment
	pyGraphs map[string]any
}

var (
	_ plugin.CapabilityFinder = (*Enricher)(nil)
	_ plugin.Diagnoser        = (*Enricher)(nil)
	_ plugin.Preparer         = (*Enricher)(nil)
	_ plugin.SourceEnricher   = (*Enricher)(nil)
	_ plugin.ReachReporter    = (*Enricher)(nil)
)

// UseSource sets the directory of the source code. A target with no
// source code gets no usage and no capabilities.
func (e *Enricher) UseSource(dir string) { e.dir = dir }

// CodeFileFailed is the diagnostic code of source files that the analysis
// could not read or parse. The scan goes on without them.
const CodeFileFailed = "source_file_failed"

// CodeFileMissing is the diagnostic code of source files that the analysis
// did not reach in its time budget.
const CodeFileMissing = "source_file_missing"

// The diagnostic codes of a call graph search that did not finish. The
// function reach of each vulnerability is then unknown.
const (
	CodeReachStopped = "reach_stopped"
	CodeReachFailed  = "reach_failed"
)

// CodeSourceMissing is the diagnostic code of imported packages with a
// vulnerability record whose code is not on the disk.
const CodeSourceMissing = "dependency_source_missing"

// maxFailedNames bounds the file names that the diagnostic of the failed
// files lists.
const maxFailedNames = 5

// Diagnostics reports the source files that the analysis skipped. One
// diagnostic names the first files and counts the rest.
func (e *Enricher) Diagnostics() []report.Diagnostic {
	var out []report.Diagnostic
	if e.symbols != nil {
		out = append(out, e.symbols.Diagnostics()...)
	}
	if e.stopped {
		msg := fmt.Sprintf("vet stopped the code analysis after %s, before it read the source files", e.o.Budget)
		if e.missing > 0 {
			msg = fmt.Sprintf("vet stopped the code analysis after %s, so the imports and calls of %d source files are not in the report", e.o.Budget, e.missing)
		}
		out = append(out, report.Diagnostic{Level: report.DiagnosticWarning, Code: CodeFileMissing, Component: Name, Message: msg})
	}
	out = append(out, e.missingDiagnostics()...)
	out = append(out, e.graphDiagnostics()...)
	if e.reachStopped {
		out = append(out, report.Diagnostic{
			Level: report.DiagnosticWarning, Code: CodeReachStopped, Component: Name,
			Message: fmt.Sprintf("vet stopped the call graph search after %s, so it does not know which vulnerable functions the code calls", e.o.Budget),
		})
	}
	if e.reachErr != nil {
		out = append(out, report.Diagnostic{
			Level: report.DiagnosticWarning, Code: CodeReachFailed, Component: Name,
			Message: fmt.Sprintf("vet could not search the call graph, so it does not know which vulnerable functions the code calls: %v", e.reachErr),
		})
	}
	if len(e.failed) == 0 {
		return out
	}
	names := make([]string, 0, min(len(e.failed), maxFailedNames))
	for _, f := range e.failed[:min(len(e.failed), maxFailedNames)] {
		names = append(names, fmt.Sprintf("%s (%s)", f.FilePath, f.Stage))
	}
	msg := fmt.Sprintf("vet could not analyze %d source files, so their imports and calls are not in the report: %s",
		len(e.failed), strings.Join(names, ", "))
	if more := len(e.failed) - len(names); more > 0 {
		msg += fmt.Sprintf(" and %d more", more)
	}
	return append(out, report.Diagnostic{Level: report.DiagnosticWarning, Code: CodeFileFailed, Component: Name, Message: msg})
}

// New returns the enricher with the default analyzer. The engine gives it
// the source directory with UseSource. A vet build with no CGO has no
// analyzer: the enricher then returns
// plugin.ErrUnavailable, and the scan records a diagnostic.
func New(o Options) *Enricher { return NewWith("", o, newAnalyzer(o)) }

// NewWith returns the enricher with an analyzer. Tests use it.
func NewWith(dir string, o Options, a Analyzer) *Enricher {
	return &Enricher{dir: dir, o: o, analyze: a}
}

// Enrich sets the usage of each package. A package that no file imports
// gets Imported false. A package of an ecosystem with no source language,
// such as a GitHub Action, gets no usage.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	if e.dir == "" {
		return nil
	}
	if err := e.load(ctx); err != nil {
		return e.err
	}
	e.provider.goModules, e.provider.goImports = nil, map[model.PackageKey]string{}
	for _, p := range pkgs {
		if p.ID.Ecosystem() != model.EcosystemGo {
			continue
		}
		e.provider.goModules = append(e.provider.goModules, cmp.Or(p.Replaces, p.ID.Name()))
		if p.Replaces != "" {
			e.provider.goImports[p.ID.Key()] = p.Replaces
		}
	}
	byModule := e.callModules()
	for _, p := range pkgs {
		if _, ok := ecosystemLanguages[p.ID.Ecosystem()]; !ok {
			p.Usage = nil
			continue
		}
		sites := map[string]int{}
		for m, files := range e.modules {
			if e.provider.provides(p.ID, m) {
				addSites(sites, files)
			}
		}
		p.Usage = usageOf(sites)
		p.Usage.Incomplete = e.stopped
		langs := ecosystemLanguages[p.ID.Ecosystem()]
		p.Usage.DynamicImport = slices.ContainsFunc(langs, func(l string) bool { return e.dynamic[l] })
		p.Usage.UnreadFiles = slices.ContainsFunc(langs, func(l string) bool { return e.unread[l] })
		p.Usage.NoSourceFiles = !p.Usage.Imported && !slices.ContainsFunc(langs, func(l string) bool { return e.languages[l] })
		p.Usage.Calls = e.callsInto(p.ID, byModule)
		p.Usage.Dynamic = e.dynamicIn(sites)
	}
	e.lookupSymbols(pkgs)
	return e.functionReach(ctx, pkgs)
}

// symbolLanguages are the languages that the symbol data covers.
var symbolLanguages = []string{"go", "rust", "python"}

// symbolEcosystems are the ecosystems of the symbol data.
var symbolEcosystems = []model.Ecosystem{model.EcosystemGo, model.EcosystemCargo, model.EcosystemPyPI}

// lookupSymbols sets the symbol records of each vulnerability of a Go or a
// Rust package. A package that only another package imports needs them
// too, so the lookup reads every package with a usage.
func (e *Enricher) lookupSymbols(pkgs []*model.Package) {
	if e.symbols == nil {
		return
	}
	var qs []symbols.Query
	var owners []*model.Package
	for _, p := range pkgs {
		if p.Usage == nil || p.Insight == nil || !slices.Contains(symbolEcosystems, p.ID.Ecosystem()) {
			continue
		}
		for _, v := range p.Insight.Vulnerabilities {
			qs = append(qs, symbols.Query{Package: p.ID, IDs: append([]string{v.ID}, v.Aliases...)})
			owners = append(owners, p)
		}
	}
	for i, recs := range e.symbols.Lookup(qs) {
		lang := ecosystemLanguages[owners[i].ID.Ecosystem()][0]
		for _, r := range recs {
			for _, site := range r.FixSites {
				if k := SymbolKey(lang, owners[i].ID.RawName(), site); k != "" {
					r.Keys = append(r.Keys, k)
				}
			}
			owners[i].Usage.Symbols = append(owners[i].Usage.Symbols, r)
		}
	}
}

// functionReach searches the call graph for the fix sites of each record.
// The engine gives the enricher every package in one call, so one graph
// links the code of the project and of each dependency on disk. The
// enricher records each answer as it is, and the engine decides the reach.
func (e *Enricher) functionReach(ctx context.Context, pkgs []*model.Package) error {
	if err := e.checkEntrypoints(); err != nil {
		return err
	}
	if e.symbols == nil || e.reach == nil {
		return nil
	}
	q, hasUnit := e.reachQuery(pkgs)
	// A batch whose records have no key searches nothing, and each record
	// still gets its answer: no symbol in the graph.
	var res ReachResult
	var failed finding.ReachCause
	if len(q.Targets) > 0 {
		var err error
		if res, failed, err = e.search(ctx, q); err != nil {
			return err
		}
	}
	for _, p := range pkgs {
		if p.Usage == nil {
			continue
		}
		for i := range p.Usage.Symbols {
			r := &p.Usage.Symbols[i]
			r.Reach = functionReachOf(r, res.Answers, hasUnit[p.ID.Key()], failed)
		}
	}
	return nil
}

// reachQuery collects the target keys of every record, and the code of
// each package whose call paths can prove a finding. The code of another
// package costs time and proves nothing.
func (e *Enricher) reachQuery(pkgs []*model.Package) (ReachQuery, map[model.PackageKey]bool) {
	q := ReachQuery{Sources: e.o.Entrypoints, SourcesOnly: e.o.EntrypointsOnly}
	hasUnit := map[model.PackageKey]bool{}
	python := false
	for _, p := range pkgs {
		if p.Usage == nil || len(p.Usage.Symbols) == 0 {
			continue
		}
		for _, r := range p.Usage.Symbols {
			q.Targets = append(q.Targets, r.Keys...)
		}
		if !p.ProvableReach() {
			continue
		}
		if u, ok := e.unitOf(p.ID); ok {
			q.Units = append(q.Units, u)
			hasUnit[p.ID.Key()] = true
			e.sources++
			if p.ID.Ecosystem() == model.EcosystemPyPI {
				python = true
			}
		} else {
			if e.noCode == nil {
				e.noCode = map[model.Ecosystem][]string{}
			}
			e.noCode[p.ID.Ecosystem()] = append(e.noCode[p.ID.Ecosystem()], p.ID.RawName())
		}
	}
	// The standard library of the interpreter joins the code of a Python
	// dependency, so a call of the library on the code of the project, as
	// Thread.start on run, is a call in the graph.
	if python {
		if u, ok := e.pythonEnv().stdlibUnit(); ok {
			q.Units = append(q.Units, u)
		}
	}
	q.Targets = slices.Compact(slices.Sorted(slices.Values(q.Targets)))
	return q, hasUnit
}

// unitOf finds the code of a package on the disk. A Python package is a
// distribution of the environment of the project.
func (e *Enricher) unitOf(id model.PackageVersion) (Unit, bool) {
	if id.Ecosystem() == model.EcosystemPyPI {
		return e.pythonEnv().unit(id)
	}
	return unitOf(e.dir, id)
}

// pythonEnv reads the Python environment of the scan root once.
func (e *Enricher) pythonEnv() *pythonEnvironment { return e.pythonEnvAt(e.dir) }

// pythonEnvAt reads the Python environment of a directory once.
func (e *Enricher) pythonEnvAt(dir string) *pythonEnvironment {
	e.pyMu.Lock()
	defer e.pyMu.Unlock()
	if env, ok := e.pyEnvs[dir]; ok {
		return env
	}
	if e.pyEnvs == nil {
		e.pyEnvs = map[string]*pythonEnvironment{}
	}
	env := readPythonEnvironment(dir)
	e.pyEnvs[dir] = env
	return env
}

// search runs the query in the budget. A search that did not finish gives
// the cause of each record. Only a usage error or a stopped scan is an
// error.
func (e *Enricher) search(ctx context.Context, q ReachQuery) (ReachResult, finding.ReachCause, error) {
	e.searched = true
	rctx := ctx
	if e.o.Budget > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, e.o.Budget)
		defer cancel()
	}
	res, err := e.reach(rctx, q)
	e.roots, e.versions = res.Roots, res.Versions
	switch {
	case err == nil:
		// A search that stopped at its budget gives each answer with no
		// path the budget uncertainty.
		e.reachStopped = res.Stopped
		return res, "", nil
	case app.ExitCode(err) == app.ExitUsage || ctx.Err() != nil:
		return res, "", err
	case errors.Is(err, context.DeadlineExceeded):
		e.reachStopped = true
		return res, finding.ReachBudget, nil
	}
	e.reachErr = err
	return res, finding.ReachAnalysisFailed, nil
}

// Search analyzes the code under dir and searches its call graph for the
// target keys, with the units as the dependency code. The reach corpus in
// test/reach runs it. A build with no CGO gives plugin.ErrUnavailable.
func Search(ctx context.Context, dir string, q ReachQuery) (ReachResult, error) {
	a, err := newAnalyzer(Options{})(ctx, dir)
	if err != nil {
		return ReachResult{}, err
	}
	if a.Reach == nil {
		return ReachResult{}, plugin.ErrUnavailable
	}
	return a.Reach(ctx, q)
}

// checkEntrypoints checks that the file of each entry point is in the
// target, so a typo exits 2 also when no search runs. The search checks
// the function.
func (e *Enricher) checkEntrypoints() error {
	for _, ep := range e.o.Entrypoints {
		file, _, err := ParseEntrypoint(ep)
		if err == nil {
			_, err = os.Stat(filepath.Join(e.dir, filepath.FromSlash(file)))
		}
		if err != nil {
			return app.UsageError(fmt.Sprintf("entry point %q names no file of the target", ep),
				"Fix the entry point. vet report root list lists the entry points that vet found.")
		}
	}
	return nil
}

// functionReachOf joins the answers for the keys of a record. One found
// key is a call. No path proves nothing unless the record lists every fix
// site, a maintainer verified it, vet read the code of the package and the
// graph has its own entry points.
func functionReachOf(r *model.SymbolRecord, answers map[string]ReachAnswer, hasUnit bool, failed finding.ReachCause) *model.FunctionReach {
	unknown := func(cause finding.ReachCause) *model.FunctionReach {
		return &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(cause)}
	}
	switch {
	case failed != "":
		return unknown(failed)
	case len(r.Keys) == 0:
		return unknown(finding.ReachNoSymbolInGraph)
	}
	var found *ReachAnswer
	var cause finding.ReachCause
	for _, k := range r.Keys {
		a, ok := answers[k]
		switch {
		case !ok:
			cause = cmp.Or(cause, finding.ReachAnalysisFailed)
		case a.Status == ReachFound:
			if found == nil || (found.TestOnly && !a.TestOnly) {
				found = &a
			}
		case a.Status == ReachUncertain && a.Uncertain != "":
			cause = cmp.Or(cause, finding.ReachCause(a.Uncertain))
		case a.Status == ReachUncertain || a.RootFallback:
			cause = cmp.Or(cause, finding.ReachNoEntryPoint)
		case a.Status == ReachNoSuchTarget && !hasUnit:
			cause = cmp.Or(cause, finding.ReachNoDependencySource)
		case a.Status == ReachNoSuchTarget:
			cause = cmp.Or(cause, finding.ReachNoSymbolInGraph)
		}
	}
	switch {
	case found != nil:
		return &model.FunctionReach{Status: model.FunctionCalled, Path: found.Path, TestOnly: found.TestOnly}
	case len(r.Keys) < len(r.FixSites):
		// A fix site with no key is not in the search, so no path to the
		// others proves nothing.
		return unknown(finding.ReachNoSymbolInGraph)
	case cause != "":
		return unknown(cause)
	case !hasUnit:
		return unknown(finding.ReachNoDependencySource)
	case r.Coverage != model.CoverageExact:
		return unknown(finding.ReachBroadRecord)
	case !r.Verified:
		return unknown(finding.ReachUnreviewedRecord)
	}
	return &model.FunctionReach{Status: model.FunctionNotFound}
}

// ReachStatus is the answer of the call graph search for one target key.
type ReachStatus string

// The statuses of a ReachAnswer, as the reach query of safedep/code names
// them.
const (
	ReachFound        ReachStatus = "found"
	ReachNotFound     ReachStatus = "not-found"
	ReachUncertain    ReachStatus = "uncertain"
	ReachNoSuchTarget ReachStatus = "no-such-target"
)

// ReachReport adds the symbol data that the scan read, and the entry
// points, the dependency code and the versions of the call graph search.
func (e *Enricher) ReachReport(info *report.ReachInfo) {
	if e.symbols == nil {
		return
	}
	info.SymbolData = true
	info.Symbols = e.symbols.Bundle()
	if e.searched {
		info.Roots, info.Versions = e.roots, e.versions
		info.Sources = &report.ReachSources{Found: e.sources}
		for eco := range e.noCode {
			info.Sources.Missing += len(e.noCodeNames(eco))
		}
	}
}

// noCodeNames lists each package of an ecosystem whose code vet did not
// find once, in order. Two manifests can list one package.
func (e *Enricher) noCodeNames(eco model.Ecosystem) []string {
	return slices.Compact(slices.Sorted(slices.Values(e.noCode[eco])))
}

// dependencyNouns name a dependency of an ecosystem in a message.
var dependencyNouns = map[model.Ecosystem][2]string{
	model.EcosystemGo:    {"Go module", "Go modules"},
	model.EcosystemCargo: {"Rust crate", "Rust crates"},
	model.EcosystemPyPI:  {"Python distribution", "Python distributions"},
}

// missingDiagnostics gives one diagnostic for each ecosystem with packages
// whose code is not on the disk. Each names the first packages and the
// command of that ecosystem that downloads them.
func (e *Enricher) missingDiagnostics() []report.Diagnostic {
	var out []report.Diagnostic
	for _, eco := range slices.Sorted(maps.Keys(e.noCode)) {
		names := e.noCodeNames(eco)
		nouns, ok := dependencyNouns[eco]
		if !ok {
			nouns = [2]string{"package", "packages"}
		}
		noun := nouns[1]
		if len(names) == 1 {
			noun = nouns[0]
		}
		list := strings.Join(names[:min(len(names), maxFailedNames)], ", ")
		if more := len(names) - maxFailedNames; more > 0 {
			list += fmt.Sprintf(" and %d more", more)
		}
		out = append(out, report.Diagnostic{
			Level: report.DiagnosticWarning, Code: CodeSourceMissing, Component: Name, Count: len(names),
			Message: fmt.Sprintf("vet found no code for %d vulnerable %s (%s), so it cannot tell if the code calls the vulnerable functions. %s",
				len(names), noun, list, finding.FetchHint(eco)),
		})
	}
	return out
}

// callModules returns the index in e.calls of each call, by its module. A
// test of each call for each package took 27 s on gitea and 88 s on vault,
// so a package tests each module once.
func (e *Enricher) callModules() map[module][]int {
	out := map[module][]int{}
	for i, c := range e.calls {
		m := module{Language: c.Language, Hint: e.hints[module{Language: c.Language, Name: c.Module}], Name: c.Module}
		out[m] = append(out[m], i)
	}
	return out
}

// callsInto returns the calls whose module the package provides, at most
// maxSites, in file and line order.
func (e *Enricher) callsInto(id model.PackageVersion, byModule map[module][]int) []model.CallSite {
	var calls []int
	for m, idx := range byModule {
		if e.provider.provides(id, m) {
			calls = append(calls, idx...)
		}
	}
	slices.Sort(calls)
	var out []model.CallSite
	for _, i := range calls[:min(len(calls), maxSites)] {
		c := e.calls[i]
		out = append(out, model.CallSite{File: c.FilePath, Line: c.Line, Callee: c.Callee})
	}
	return out
}

// dynamicIn returns the dynamic sites of the files that import a package,
// at most maxSites.
func (e *Enricher) dynamicIn(files map[string]int) []model.DynamicSite {
	var out []model.DynamicSite
	for _, d := range e.sites {
		if _, ok := files[d.File]; ok {
			out = append(out, d)
			if len(out) == maxSites {
				break
			}
		}
	}
	return out
}

// usageOf returns the usage of a package from the first import line of
// each file that imports it.
func usageOf(sites map[string]int) *model.Usage {
	u := &model.Usage{Imported: len(sites) > 0, TestOnly: len(sites) > 0}
	for f := range sites {
		if !testFile(f) {
			u.TestOnly = false
		}
	}
	files := slices.Sorted(maps.Keys(sites))
	if len(files) > maxFiles {
		files = files[:maxFiles]
	}
	for _, f := range files {
		u.Files = append(u.Files, f)
		u.Imports = append(u.Imports, model.ImportSite{File: f, Line: sites[f]})
	}
	return u
}

// addSites keeps the first line of each file.
func addSites(sites, add map[string]int) {
	for f, line := range add {
		if l, ok := sites[f]; !ok || line < l {
			sites[f] = line
		}
	}
}

// testFile reports whether a file is a test file, by the globs that the
// project graph of safedep/code also reads.
func testFile(name string) bool {
	return slices.ContainsFunc(fileindex.DefaultTestPaths, func(g string) bool { return pathglob.Match(g, name) })
}

// Prepare indexes the source files at scan start, while the network
// enrichers run. Enrich and Capabilities then wait for the same load, and
// they report its error.
func (e *Enricher) Prepare(ctx context.Context) error {
	if e.dir == "" {
		return nil
	}
	return e.load(ctx)
}

// load analyzes the target once for the scan.
func (e *Enricher) load(ctx context.Context) error {
	e.once.Do(func() { e.err = e.index(ctx) })
	return e.err
}

func (e *Enricher) index(ctx context.Context) error {
	actx := ctx
	if e.o.Budget > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(ctx, e.o.Budget)
		defer cancel()
	}
	a, err := e.analyze(actx, e.dir)
	if err != nil && (ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded)) {
		return err
	}
	e.stopped = err != nil
	counts := map[fileindex.FileStatus]int{}
	for _, st := range a.Files {
		counts[st]++
	}
	e.missing = counts[fileindex.FileMissing]
	log.Debugf("code index: %d source files, %d cached, %d indexed, %d missing", len(a.Files), counts[fileindex.FileCached], counts[fileindex.FileIndexed], e.missing)
	if e.own, err = ownRoots(e.dir); err != nil {
		return err
	}
	e.matches = e.external(a.Matches)
	e.dynamic, e.languages, e.unread = a.DynamicImports, a.Languages, a.Unread
	if e.o.Symbols != nil && slices.ContainsFunc(symbolLanguages, func(l string) bool { return e.languages[l] }) {
		e.o.Symbols.Prepare(ctx)
		e.symbols = e.o.Symbols
	}
	e.calls, e.sites = a.Calls, a.Dynamic
	e.reach = a.Reach
	slices.SortFunc(e.calls, func(x, y ExternalCall) int {
		return cmp.Or(cmp.Compare(x.FilePath, y.FilePath), cmp.Compare(x.Line, y.Line), cmp.Compare(x.Callee, y.Callee))
	})
	slices.SortFunc(e.sites, func(x, y model.DynamicSite) int {
		return cmp.Or(cmp.Compare(x.File, y.File), cmp.Compare(x.Line, y.Line), cmp.Compare(x.Kind, y.Kind))
	})
	e.failed = a.Failed
	for i := range e.failed {
		e.failed[i].FilePath = filepath.ToSlash(e.failed[i].FilePath)
	}
	evs := a.Usage
	autoload, err := readAutoload(e.dir)
	if err != nil {
		return err
	}
	e.modules = map[module]map[string]int{}
	e.hints = map[module]string{}
	for _, ev := range evs {
		m := module{Language: ev.Language, Hint: ev.PackageHint, Name: ev.ModuleName}
		if e.modules[m] == nil {
			e.modules[m] = map[string]int{}
		}
		e.hints[module{Language: ev.Language, Name: ev.ModuleName}] = ev.PackageHint
		addSites(e.modules[m], map[string]int{filepath.ToSlash(ev.FilePath): int(ev.Line)})
	}
	e.provider = provider{autoload: autoload}
	return nil
}

// external returns the matches that do not call into the project itself.
// The analyzer gives each path relative to the target, and the report
// writes it with "/".
func (e *Enricher) external(matches []Match) []Match {
	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		if inRoots(m.Callee, e.own) {
			continue
		}
		m.FilePath = filepath.ToSlash(m.FilePath)
		out = append(out, m)
	}
	return out
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// rootModule returns the package part of an import path: "lodash" for
// "lodash/fp", "@scope/pkg" for "@scope/pkg/sub", and "yaml" for
// "yaml.loader".
func rootModule(m string) string {
	if strings.HasPrefix(m, "@") {
		parts := strings.SplitN(m, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return m
	}
	if i := strings.IndexAny(m, "/."); i > 0 {
		return m[:i]
	}
	return m
}

// skippedDirs are the directories that hold installed, vendored or bundled
// code, not the code of the project, at any depth. A web app of a
// monorepo keeps its bundle in web/dist.
var skippedDirs = []string{"node_modules", "vendor", ".git", ".venv", "venv", "dist", "__pycache__"}

// skippedRootDirs hold built code only directly under the target. A Go
// package of the project can have the name build, as internal/build, and
// its calls must stay in the call graph.
var skippedRootDirs = []string{"build", "target"}

// skippedDir reports a directory of installed or built code. rel is the
// path of the directory from the target, with "/".
func skippedDir(rel string) bool {
	return slices.Contains(skippedDirs, path.Base(rel)) || slices.Contains(skippedRootDirs, rel)
}

// bundledFile matches a minified or bundled script, such as a vendored
// swagger-ui-bundle.js. It holds a copy of other packages, and its short
// global names, such as ai, look like the names of npm packages.
var bundledFile = regexp.MustCompile(`(\.min|[.-]bundle)\.[cm]?js$`)

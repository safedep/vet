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

	"github.com/safedep/vet/v2/internal/pathglob"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the registered name of the enricher and the config key under
// plugins. It is off by default, because it parses each source file.
const Name = "codeusage"

// Version changes when the mapping or the signatures change.
const Version = "8"

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

// DynamicSite is one line of a source file that the analysis cannot follow.
type DynamicSite struct {
	FilePath string
	Line     int
	Kind     string
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
	Files map[string]string
	// DynamicImports holds the languages of the files that import a module
	// by a computed name.
	DynamicImports map[string]bool
	Calls          []ExternalCall
	Dynamic        []DynamicSite
}

// DefaultBudget bounds the code analysis when plugins.codeusage.options
// sets no budget.
const DefaultBudget = 5 * time.Minute

// Settings are plugins.codeusage.options.
type Settings struct {
	// Reach is the reach level of the vulnerability findings: off, import
	// or function. The default is function. --reach overrides it.
	Reach string `json:"reach,omitempty" jsonschema:"enum=off,enum=import,enum=function"`
	// Budget bounds the time of the code analysis, as 90s or 10m. The
	// default is 5m.
	Budget string `json:"budget,omitempty"`
}

// ParseSettings reads plugins.codeusage.options.
func ParseSettings(cfg plugin.Config) (report.ReachLevel, time.Duration, error) {
	var s Settings
	if err := cfg.Decode(&s); err != nil {
		return "", 0, err
	}
	level, err := report.ParseReachLevel(s.Reach)
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", Name, err)
	}
	if s.Budget == "" {
		return level, DefaultBudget, nil
	}
	budget, err := time.ParseDuration(s.Budget)
	if err != nil || budget <= 0 {
		return "", 0, fmt.Errorf("%s: budget %q is not a positive duration such as 90s or 10m", Name, s.Budget)
	}
	return level, budget, nil
}

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

// FileMissing is the status of a file that the analysis did not reach in
// its time budget.
const FileMissing = "missing"

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
	calls   []ExternalCall
	sites   []DynamicSite
	// hints holds the package hint of each imported module, by language
	// and name, for the calls that name the module only.
	hints    map[module]string
	own      []string
	provider provider
	err      error
}

var (
	_ plugin.CapabilityFinder = (*Enricher)(nil)
	_ plugin.Diagnoser        = (*Enricher)(nil)
	_ plugin.Preparer         = (*Enricher)(nil)
	_ plugin.SourceEnricher   = (*Enricher)(nil)
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

// maxFailedNames bounds the file names that the diagnostic of the failed
// files lists.
const maxFailedNames = 5

// Diagnostics reports the source files that the analysis skipped. One
// diagnostic names the first files and counts the rest.
func (e *Enricher) Diagnostics() []report.Diagnostic {
	var out []report.Diagnostic
	if e.stopped {
		msg := fmt.Sprintf("vet stopped the code analysis after %s, before it read the source files", e.o.Budget)
		if e.missing > 0 {
			msg = fmt.Sprintf("vet stopped the code analysis after %s, so the imports and calls of %d source files are not in the report", e.o.Budget, e.missing)
		}
		out = append(out, report.Diagnostic{Level: report.DiagnosticWarning, Code: CodeFileMissing, Component: Name, Message: msg})
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
		p.Usage.DynamicImport = slices.ContainsFunc(ecosystemLanguages[p.ID.Ecosystem()], func(l string) bool { return e.dynamic[l] })
		p.Usage.Calls = e.callsInto(p.ID)
		p.Usage.Dynamic = e.dynamicIn(sites)
	}
	return nil
}

// callsInto returns the calls whose module the package provides, at most
// maxSites, in file and line order.
func (e *Enricher) callsInto(id model.PackageVersion) []model.CallSite {
	var out []model.CallSite
	for _, c := range e.calls {
		m := module{Language: c.Language, Hint: e.hints[module{Language: c.Language, Name: c.Module}], Name: c.Module}
		if e.provider.provides(id, m) {
			out = append(out, model.CallSite{File: c.FilePath, Line: c.Line, Callee: c.Callee})
			if len(out) == maxSites {
				break
			}
		}
	}
	return out
}

// dynamicIn returns the dynamic sites of the files that import a package,
// at most maxSites.
func (e *Enricher) dynamicIn(files map[string]int) []model.DynamicSite {
	var out []model.DynamicSite
	for _, d := range e.sites {
		if _, ok := files[d.FilePath]; ok {
			out = append(out, model.DynamicSite{File: d.FilePath, Line: d.Line, Kind: d.Kind})
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
	counts := map[string]int{}
	for _, st := range a.Files {
		counts[st]++
	}
	e.missing = counts[FileMissing]
	log.Debugf("code index: %d source files, %d cached, %d indexed, %d missing", len(a.Files), counts["cached"], counts["indexed"], e.missing)
	if e.own, err = ownRoots(e.dir); err != nil {
		return err
	}
	e.matches = e.external(a.Matches)
	e.dynamic = a.DynamicImports
	e.calls, e.sites = a.Calls, a.Dynamic
	slices.SortFunc(e.calls, func(x, y ExternalCall) int {
		return cmp.Or(cmp.Compare(x.FilePath, y.FilePath), cmp.Compare(x.Line, y.Line), cmp.Compare(x.Callee, y.Callee))
	})
	slices.SortFunc(e.sites, func(x, y DynamicSite) int {
		return cmp.Or(cmp.Compare(x.FilePath, y.FilePath), cmp.Compare(x.Line, y.Line), cmp.Compare(x.Kind, y.Kind))
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

// skippedDirs are the directories that hold installed or built code, not
// the code of the project.
var skippedDirs = []string{"node_modules", "vendor", ".git", ".venv", "venv", "dist", "build", "target", "__pycache__"}

func skippedDir(name string) bool { return slices.Contains(skippedDirs, name) }

// bundledFile matches a minified or bundled script, such as a vendored
// swagger-ui-bundle.js. It holds a copy of other packages, and its short
// global names, such as ai, look like the names of npm packages.
var bundledFile = regexp.MustCompile(`(\.min|[.-]bundle)\.[cm]?js$`)

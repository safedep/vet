// Package codeusage is the enricher of code usage evidence and of the
// xBOM (decisions P8). It reads the source files of the target once. It
// finds the imports and sets model.Package.Usage: whether the code imports
// the package, and in which files. The engine adds the usage to each
// package finding as evidence. It also matches the code signatures on the
// call graph of each file, and each signature that matches is a capability
// of the application, such as a call to an LLM provider.
package codeusage

import (
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
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the registered name of the enricher and the config key under
// plugins. It is off by default, because it parses each source file.
const Name = "codeusage"

// Version changes when the mapping or the signatures change.
const Version = "6"

// maxFiles bounds the files that a package usage lists.
const maxFiles = 20

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
}

// indexRetention is how long the code index keeps a file that no scan
// reads. An index never goes stale, since its key holds the hash of the
// file, so only disk space bounds it.
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

	once     sync.Once
	modules  map[module]map[string]int
	matches  []Match
	failed   []FileFailure
	stopped  bool
	missing  int
	own      []string
	provider provider
	err      error
}

var (
	_ plugin.CapabilityFinder = (*Enricher)(nil)
	_ plugin.Diagnoser        = (*Enricher)(nil)
	_ plugin.Preparer         = (*Enricher)(nil)
)

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

// New returns the enricher of a directory with the default analyzer. A
// vet build with no CGO has no analyzer: the enricher then returns
// plugin.ErrUnavailable, and the scan records a diagnostic.
func New(dir string, o Options) *Enricher { return NewWith(dir, o, newAnalyzer(o)) }

// NewWith returns the enricher with an analyzer. Tests use it.
func NewWith(dir string, o Options, a Analyzer) *Enricher {
	return &Enricher{dir: dir, o: o, analyze: a}
}

// Enrich sets the usage of each package. A package that no file imports
// gets Imported false. A package of an ecosystem with no source language,
// such as a GitHub Action, gets no usage.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
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
	}
	return nil
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
func (e *Enricher) Prepare(ctx context.Context) error { return e.load(ctx) }

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
	for _, ev := range evs {
		m := module{Language: ev.Language, Hint: ev.PackageHint, Name: ev.ModuleName}
		if e.modules[m] == nil {
			e.modules[m] = map[string]int{}
		}
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

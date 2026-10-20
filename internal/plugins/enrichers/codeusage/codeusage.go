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
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the registered name of the enricher and the config key under
// plugins. It is off by default, because it parses each source file.
const Name = "codeusage"

// Version changes when the mapping or the signatures change.
const Version = "5"

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
}

// Analyzer analyzes the source files under a directory.
type Analyzer func(ctx context.Context, dir string) (Analysis, error)

// Options are the options of the enricher.
type Options struct {
	// BaseRef is the base ref of pull request mode. Each capability then
	// gets the change against the base commit.
	BaseRef string
}

// Enricher sets model.Package.Usage from the imports of the target, and
// finds the capabilities of the target.
type Enricher struct {
	dir     string
	o       Options
	analyze Analyzer

	once     sync.Once
	modules  map[module][]string
	matches  []Match
	failed   []FileFailure
	own      []string
	provider provider
	err      error
}

var (
	_ plugin.CapabilityFinder = (*Enricher)(nil)
	_ plugin.Diagnoser        = (*Enricher)(nil)
)

// CodeFileFailed is the diagnostic code of source files that the analysis
// could not read or parse. The scan goes on without them.
const CodeFileFailed = "source_file_failed"

// maxFailedNames bounds the file names that the diagnostic of the failed
// files lists.
const maxFailedNames = 5

// Diagnostics reports the source files that the analysis skipped. One
// diagnostic names the first files and counts the rest.
func (e *Enricher) Diagnostics() []report.Diagnostic {
	if len(e.failed) == 0 {
		return nil
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
	return []report.Diagnostic{{Level: report.DiagnosticWarning, Code: CodeFileFailed, Component: Name, Message: msg}}
}

// New returns the enricher of a directory with the default analyzer. A
// vet build with no CGO has no analyzer: the enricher then returns
// plugin.ErrUnavailable, and the scan records a diagnostic.
func New(dir string, o Options) *Enricher { return NewWith(dir, o, defaultAnalyzer) }

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
		set := map[string]bool{}
		for m, files := range e.modules {
			if e.provider.provides(p.ID, m) {
				for _, f := range files {
					set[f] = true
				}
			}
		}
		p.Usage = &model.Usage{Imported: len(set) > 0, Files: sortedFiles(set)}
	}
	return nil
}

// load analyzes the target once for the scan.
func (e *Enricher) load(ctx context.Context) error {
	e.once.Do(func() { e.err = e.index(ctx) })
	return e.err
}

func (e *Enricher) index(ctx context.Context) error {
	a, err := e.analyze(ctx, e.dir)
	if err != nil {
		return err
	}
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
	sets := map[module]map[string]bool{}
	for _, ev := range evs {
		m := module{Language: ev.Language, Hint: ev.PackageHint, Name: ev.ModuleName}
		if sets[m] == nil {
			sets[m] = map[string]bool{}
		}
		sets[m][filepath.ToSlash(ev.FilePath)] = true
	}
	e.modules = make(map[module][]string, len(sets))
	for m, set := range sets {
		e.modules[m] = sortedFiles(set)
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

// sortedFiles returns the files of a set in order, at most maxFiles.
func sortedFiles(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	files := make([]string, 0, len(set))
	for f := range set {
		files = append(files, f)
	}
	sort.Strings(files)
	if len(files) > maxFiles {
		files = files[:maxFiles]
	}
	return files
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

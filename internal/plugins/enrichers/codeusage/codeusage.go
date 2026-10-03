// Package codeusage is the enricher of code usage evidence (decisions P8).
// It reads the source files of the target once, finds the imports, and
// sets model.Package.Usage: whether the code imports the package, and in
// which files. The scan file keeps the usage with the package, and the
// engine adds it to each package finding as evidence.
package codeusage

import (
	"context"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/model"
)

// Name is the registered name of the enricher and the config key under
// plugins. It is off by default, because it parses each source file.
const Name = "codeusage"

// Version changes when the mapping changes.
const Version = "2"

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

// Analyzer finds the imports of the source files under a directory.
type Analyzer func(ctx context.Context, dir string) ([]Evidence, error)

// Enricher sets model.Package.Usage from the imports of the target.
type Enricher struct {
	dir     string
	analyze Analyzer

	once     sync.Once
	modules  map[module][]string
	provider provider
	err      error
}

// New returns the enricher of a directory with the default analyzer. A
// vet build with no CGO has no analyzer: the enricher then returns
// plugin.ErrUnavailable, and the scan records a diagnostic.
func New(dir string) *Enricher { return NewWith(dir, defaultAnalyzer) }

// NewWith returns the enricher with an analyzer. Tests use it.
func NewWith(dir string, a Analyzer) *Enricher { return &Enricher{dir: dir, analyze: a} }

// Enrich sets the usage of each package. A package that no file imports
// gets Imported false. A package of an ecosystem with no source language,
// such as a GitHub Action, gets no usage.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	e.once.Do(func() { e.err = e.index(ctx) })
	if e.err != nil {
		return e.err
	}
	for _, p := range pkgs {
		if _, ok := ecosystemLanguages[p.ID.Ecosystem]; !ok {
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

func (e *Enricher) index(ctx context.Context) error {
	evs, err := e.analyze(ctx, e.dir)
	if err != nil {
		return err
	}
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
		sets[m][e.rel(ev.FilePath)] = true
	}
	e.modules = make(map[module][]string, len(sets))
	for m, set := range sets {
		e.modules[m] = sortedFiles(set)
	}
	e.provider = provider{autoload: autoload}
	return nil
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

// rel returns the path of a file relative to the scanned directory, with
// "/", as every other path of the report. A path outside it stays as the
// analyzer gave it.
func (e *Enricher) rel(file string) string {
	if !filepath.IsAbs(file) {
		return filepath.ToSlash(file)
	}
	dir, err := filepath.Abs(e.dir)
	if err != nil {
		return file
	}
	r, err := filepath.Rel(dir, file)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return file
	}
	return filepath.ToSlash(r)
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

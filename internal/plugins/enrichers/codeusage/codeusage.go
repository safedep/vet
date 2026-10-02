// Package codeusage is the enricher of code usage evidence (decisions P8).
// It reads the source files of the target once, finds the imports, and
// sets model.Package.Usage: whether the code imports the package, and in
// which files. The scan file keeps the usage with the package, and the
// engine adds it to each package finding as evidence.
package codeusage

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/model"
)

// Name is the registered name of the enricher and the config key under
// plugins. It is off by default, because it parses each source file.
const Name = "codeusage"

// Version changes when the mapping changes.
const Version = "1"

// maxFiles bounds the files that a package usage lists.
const maxFiles = 20

// Evidence is one import of a module in a source file.
type Evidence struct {
	// PackageHint is the package that holds the module, as the analysis
	// guesses it, for example "yaml" for "import yaml".
	PackageHint string
	ModuleName  string
	FilePath    string
	Line        uint
}

// Analyzer finds the imports of the source files under a directory.
type Analyzer func(ctx context.Context, dir string) ([]Evidence, error)

// Enricher sets model.Package.Usage from the imports of the target.
type Enricher struct {
	dir     string
	analyze Analyzer

	once  sync.Once
	usage map[string][]string
	err   error
}

// New returns the enricher of a directory with the default analyzer. A
// vet build with no CGO has no analyzer: the enricher then returns
// plugin.ErrUnavailable, and the scan records a diagnostic.
func New(dir string) *Enricher { return NewWith(dir, defaultAnalyzer) }

// NewWith returns the enricher with an analyzer. Tests use it.
func NewWith(dir string, a Analyzer) *Enricher { return &Enricher{dir: dir, analyze: a} }

// Enrich sets the usage of each package. A package that no file imports
// gets Imported false.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	e.once.Do(func() { e.usage, e.err = e.index(ctx) })
	if e.err != nil {
		return e.err
	}
	for _, p := range pkgs {
		u := &model.Usage{}
		for _, k := range keys(p.ID) {
			if files, ok := e.usage[k]; ok {
				u.Imported, u.Files = true, files
				break
			}
		}
		p.Usage = u
	}
	return nil
}

func (e *Enricher) index(ctx context.Context) (map[string][]string, error) {
	evs, err := e.analyze(ctx, e.dir)
	if err != nil {
		return nil, err
	}
	sets := map[string]map[string]bool{}
	add := func(k, file string) {
		if k == "" {
			return
		}
		if sets[k] == nil {
			sets[k] = map[string]bool{}
		}
		sets[k][file] = true
	}
	for _, ev := range evs {
		add(normalize(ev.PackageHint), ev.FilePath)
		add(normalize(rootModule(ev.ModuleName)), ev.FilePath)
	}
	out := make(map[string][]string, len(sets))
	for k, set := range sets {
		files := make([]string, 0, len(set))
		for f := range set {
			files = append(files, f)
		}
		sort.Strings(files)
		if len(files) > maxFiles {
			files = files[:maxFiles]
		}
		out[k] = files
	}
	return out, nil
}

// keys returns the names under which code imports a package: the name, and
// for PyPI the name with underscores.
func keys(id model.PackageID) []string {
	name := normalize(id.QualifiedName())
	if id.Ecosystem == model.EcosystemPyPI {
		return []string{name, strings.ReplaceAll(name, "-", "_")}
	}
	return []string{name}
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

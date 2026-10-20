//go:build cgo

package codeusage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/safedep/code/core"
	"github.com/safedep/code/fileindex"
	"github.com/safedep/code/fileindex/store/localdbstore"
	"github.com/safedep/code/fs"
	"github.com/safedep/code/lang"
	"github.com/safedep/code/plugin/callgraph"
	"github.com/safedep/code/plugin/depsusage"
	"github.com/safedep/code/plugin/indexer"
	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
)

// skipPatterns match the paths under root that vet does not analyze. They
// look only below root, so a target such as /ci/build/app keeps its code,
// and they take both path separators for Windows.
func skipPatterns(root string) []*regexp.Regexp {
	const sep = `[\\/]`
	names := strings.Join(regexpQuoted(skippedDirs), "|")
	return []*regexp.Regexp{
		regexp.MustCompile(`^` + regexp.QuoteMeta(root) + sep + `(?:.*` + sep + `)?(?:` + names + `)(?:` + sep + `|$)`),
		bundledFile,
	}
}

func regexpQuoted(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = regexp.QuoteMeta(n)
	}
	return out
}

// newAnalyzer returns the analyzer that indexes the source files with
// tree-sitter, which needs CGO. With a cache, the index and the analysis of
// each file stay in cache.db, so a later scan parses only the changed files.
func newAnalyzer(o Options) Analyzer {
	return func(ctx context.Context, dir string) (Analysis, error) {
		return analyzeDir(ctx, dir, o.Cache)
	}
}

func analyzeDir(ctx context.Context, dir string, cache localdb.Manager) (Analysis, error) {
	fileAnalysis, err := newFilePlugin()
	if err != nil {
		return Analysis{}, err
	}
	langs, err := lang.AllLanguages()
	if err != nil {
		return Analysis{}, err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return Analysis{}, err
	}
	fileSystem, err := fs.NewLocalFileSystem(fs.LocalFileSystemConfig{AppDirectories: []string{root}, ExcludePatterns: skipPatterns(root)})
	if err != nil {
		return Analysis{}, err
	}
	opts := indexer.Options{Languages: langs, Plugins: []core.Plugin{fileAnalysis}}
	if cache != nil {
		// A broken cache.db costs time, not the code usage.
		if opts.Store, err = localdbstore.New(ctx, cache); err != nil {
			log.Warnf("code index: %v. vet parses every file", err)
			opts.Store = nil
		}
	}
	ix, err := indexer.New(opts)
	if err != nil {
		return Analysis{}, err
	}
	res, runErr := ix.Run(ctx, fileSystem)
	if res == nil {
		return Analysis{}, fmt.Errorf("code analysis: %w", runErr)
	}
	out := Analysis{Usage: fileAnalysis.usage, Matches: fileAnalysis.matches, Files: make(map[string]string, len(res.Files))}
	importLines(out.Usage, res.Indexes)
	out.DynamicImports = dynamicImports(res.Indexes)
	out.Calls = externalCalls(res.Indexes)
	out.Dynamic = dynamicSites(res.Indexes)
	out.Languages, out.Unread = map[string]bool{}, map[string]bool{}
	for f, st := range res.Files {
		out.Files[f] = string(st)
		out.Languages[languageOf(f)] = true
		if st == fileindex.FileFailed || st == fileindex.FileTruncated {
			out.Unread[languageOf(f)] = true
		}
	}
	for _, f := range res.Report.Failed {
		// The indexer marks a file that the budget cut in the plugin as
		// indexed, because its index is complete. Its usage is not.
		if errors.Is(f.Err, context.DeadlineExceeded) || errors.Is(f.Err, context.Canceled) {
			out.Files[f.File] = FileMissing
			continue
		}
		out.Failed = append(out.Failed, FileFailure{FilePath: f.File, Stage: string(f.Stage), Err: f.Err.Error()})
		out.Unread[languageOf(f.File)] = true
	}
	if runErr != nil {
		return out, fmt.Errorf("code analysis: %w", runErr)
	}
	return out, nil
}

// importLines moves the line of each usage evidence to the import of its
// module. The usage plugin gives the line of the first use, but a person
// looks for the import.
func importLines(evs []Evidence, indexes []*fileindex.Index) {
	lines := map[string]map[string]int{}
	for _, ix := range indexes {
		for _, imp := range ix.Imports {
			if lines[ix.Path] == nil {
				lines[ix.Path] = map[string]int{}
			}
			if l, ok := lines[ix.Path][imp.Module]; !ok || imp.Line < l {
				lines[ix.Path][imp.Module] = imp.Line
			}
		}
	}
	for i, ev := range evs {
		if l, ok := lines[ev.FilePath][ev.ModuleName]; ok {
			evs[i].Line = uint(l)
		}
	}
}

// dynamicImports returns the languages of the files that import a module
// by a computed name, as import(name) or importlib.import_module(name).
func dynamicImports(indexes []*fileindex.Index) map[string]bool {
	out := map[string]bool{}
	for _, ix := range indexes {
		if slices.ContainsFunc(ix.Imports, func(imp fileindex.Import) bool { return imp.Kind == fileindex.ImportDynamicComputed }) {
			out[string(ix.Language)] = true
		}
	}
	return out
}

// externalCalls returns the calls of each file into an imported module.
// The module is the import whose namespace is the longest start of the call
// target. A bare name that no import binds names no module, so it is not a
// call into a package.
func externalCalls(indexes []*fileindex.Index) []ExternalCall {
	var out []ExternalCall
	for _, ix := range indexes {
		for _, c := range ix.ExternalCalls() {
			targets := c.Targets
			if len(targets) == 0 {
				targets = []string{c.Callee}
			}
			for _, target := range targets {
				if mod := importOf(ix.Imports, target); mod != "" {
					out = append(out, ExternalCall{FilePath: ix.Path, Line: c.Line, Language: string(ix.Language), Callee: target, Module: mod})
					break
				}
			}
		}
	}
	return out
}

func importOf(imports []fileindex.Import, target string) string {
	best, module := "", ""
	for _, imp := range imports {
		ns := imp.Namespace
		if ns == "" || len(ns) <= len(best) {
			continue
		}
		if target == ns || strings.HasPrefix(target, ns+fileindex.Separator) {
			best, module = ns, imp.Module
		}
	}
	return module
}

func dynamicSites(indexes []*fileindex.Index) []DynamicSite {
	var out []DynamicSite
	for _, ix := range indexes {
		for _, f := range ix.DynamicSites() {
			out = append(out, DynamicSite{FilePath: ix.Path, Line: f.Line, Kind: string(f.Kind)})
		}
	}
	return out
}

// filePlugin is the analysis of one file that the indexer caches: the usage
// evidence of depsusage and the signature matches on the call graph. The
// indexer runs it on one goroutine, so it needs no lock.
type filePlugin struct {
	usagePlugin core.TreePlugin
	graphPlugin core.TreePlugin
	version     string
	languages   []core.LanguageCode

	file    fileResult
	usage   []Evidence
	matches []Match
}

// fileResult is the stored artifact of one file.
type fileResult struct {
	Usage   []Evidence `json:"usage,omitempty"`
	Matches []Match    `json:"matches,omitempty"`
}

var _ indexer.CachedPlugin = (*filePlugin)(nil)

func newFilePlugin() (*filePlugin, error) {
	sigs, err := loadSignatures()
	if err != nil {
		return nil, err
	}
	hash, err := signaturesHash()
	if err != nil {
		return nil, err
	}
	matcher, err := callgraph.NewSignatureMatcher(sigs)
	if err != nil {
		return nil, err
	}
	p := &filePlugin{version: Version + "-" + hash + "-" + codeModuleVersion()}
	p.usagePlugin = depsusage.NewDependencyUsagePlugin(func(_ context.Context, ev *depsusage.UsageEvidence) error {
		p.file.Usage = append(p.file.Usage, Evidence{
			PackageHint: ev.PackageHint, ModuleName: ev.ModuleName, Language: languageOf(ev.FilePath), FilePath: ev.FilePath, Line: ev.Line,
		})
		return nil
	})
	p.graphPlugin = callgraph.NewCallGraphPlugin(func(_ context.Context, cg *callgraph.CallGraph) error {
		ms, err := matches(matcher, cg)
		p.file.Matches = append(p.file.Matches, ms...)
		return err
	})
	p.languages = slices.Compact(slices.Sorted(slices.Values(append(p.usagePlugin.SupportedLanguages(), p.graphPlugin.SupportedLanguages()...))))
	return p, nil
}

// codeModuleVersion is the version of safedep/code in this build. A new
// release can change what depsusage and the call graph find in a file
// without a change of fileindex.Version, so the artifact key holds it. A
// test binary has no dependency list and gets "unknown". A local replace
// keys by its path only, so a developer clears the cache after an edit.
func codeModuleVersion() string {
	info, _ := debug.ReadBuildInfo()
	return moduleVersion(info, "github.com/safedep/code")
}

func moduleVersion(info *debug.BuildInfo, path string) string {
	if info == nil {
		return "unknown"
	}
	for _, m := range info.Deps {
		if m.Path != path {
			continue
		}
		if m.Replace != nil {
			return m.Replace.Path + "@" + m.Replace.Version + m.Replace.Sum
		}
		return m.Version
	}
	return "unknown"
}

func (p *filePlugin) Name() string                            { return "vet-" + Name }
func (p *filePlugin) Version() string                         { return p.version }
func (p *filePlugin) SupportedLanguages() []core.LanguageCode { return p.languages }

// Analyze runs both plugins on the tree. A plugin that fails keeps what the
// other found, and the indexer stores no artifact, so the next scan tries
// the file again.
func (p *filePlugin) Analyze(ctx context.Context, _ core.File, tree core.ParseTree) ([]byte, error) {
	p.file = fileResult{}
	language, err := tree.Language()
	if err != nil {
		return nil, err
	}
	code := language.Meta().Code
	var errs []error
	for _, pl := range []core.TreePlugin{p.usagePlugin, p.graphPlugin} {
		if slices.Contains(pl.SupportedLanguages(), code) {
			if err := pl.AnalyzeTree(ctx, tree); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", pl.Name(), err))
			}
		}
	}
	p.file.Usage = firstUses(p.file.Usage)
	p.keep(p.file)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return json.Marshal(p.file)
}

// firstUses keeps the first use of each module. The enricher needs one
// line for each file and module, and a file can use a module thousands of
// times.
func firstUses(evs []Evidence) []Evidence {
	first := map[Evidence]int{}
	var out []Evidence
	for _, ev := range evs {
		k := ev
		k.Line = 0
		if i, ok := first[k]; ok {
			out[i].Line = min(out[i].Line, ev.Line)
			continue
		}
		first[k] = len(out)
		out = append(out, ev)
	}
	return out
}

// Restore takes the stored artifact of an unchanged file.
func (p *filePlugin) Restore(_ context.Context, _ core.File, data []byte) error {
	var r fileResult
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	p.keep(r)
	return nil
}

func (p *filePlugin) keep(r fileResult) {
	p.usage = append(p.usage, r.Usage...)
	p.matches = append(p.matches, r.Matches...)
}

// matches returns one match for each call that matches a signature
// condition in the call graph of a file.
func matches(matcher *callgraph.SignatureMatcher, cg *callgraph.CallGraph) ([]Match, error) {
	results, err := matcher.MatchSignatures(cg)
	if err != nil || len(results) == 0 {
		return nil, err
	}
	var out []Match
	for _, r := range results {
		sig := signatureOf(r.MatchedSignature)
		for _, c := range r.MatchedConditions {
			for _, ev := range c.Evidences {
				m := Match{
					Signature: sig, FilePath: r.FilePath, Language: string(r.MatchedLanguageCode),
					Line: int(ev.Site.StartLine), Column: int(ev.Site.StartColumn),
				}
				if ev.Callee != nil {
					m.Callee = ev.Callee.Namespace
				}
				out = append(out, m)
			}
		}
	}
	return out, nil
}

func languageOf(file string) string {
	if l, ok := lang.ResolveLanguageFromPath(file); ok {
		return string(l.Meta().Code)
	}
	return ""
}

// Available reports that this build has code analysis.
func Available() bool { return true }

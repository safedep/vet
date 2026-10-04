//go:build cgo

package codeusage

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/safedep/code/core"
	"github.com/safedep/code/fs"
	"github.com/safedep/code/lang"
	"github.com/safedep/code/parser"
	"github.com/safedep/code/plugin"
	"github.com/safedep/code/plugin/callgraph"
	"github.com/safedep/code/plugin/depsusage"
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

// defaultAnalyzer parses the source files with tree-sitter, which needs
// CGO. One pass finds the imports and matches the code signatures on the
// call graph of each file.
func defaultAnalyzer(ctx context.Context, dir string) (Analysis, error) {
	sigs, err := loadSignatures()
	if err != nil {
		return Analysis{}, err
	}
	matcher, err := callgraph.NewSignatureMatcher(sigs)
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
	walker, err := fs.NewSourceWalker(fs.SourceWalkerConfig{}, langs)
	if err != nil {
		return Analysis{}, err
	}
	tree, err := parser.NewWalkingParser(walker, langs)
	if err != nil {
		return Analysis{}, err
	}

	var mu sync.Mutex
	var out Analysis
	var collectUsage depsusage.DependencyUsageCallback = func(_ context.Context, ev *depsusage.UsageEvidence) error {
		mu.Lock()
		defer mu.Unlock()
		out.Usage = append(out.Usage, Evidence{
			PackageHint: ev.PackageHint, ModuleName: ev.ModuleName, Language: languageOf(ev.FilePath), FilePath: ev.FilePath, Line: ev.Line,
		})
		return nil
	}
	var collectMatches callgraph.CallgraphCallback = func(_ context.Context, cg *callgraph.CallGraph) error {
		ms, err := matches(matcher, cg)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		out.Matches = append(out.Matches, ms...)
		return nil
	}
	exec, err := plugin.NewTreeWalkPluginExecutor(tree, []core.Plugin{
		depsusage.NewDependencyUsagePlugin(collectUsage),
		callgraph.NewCallGraphPlugin(collectMatches),
	})
	if err != nil {
		return Analysis{}, err
	}
	if err := exec.Execute(ctx, fileSystem); err != nil {
		return Analysis{}, fmt.Errorf("code analysis: %w", err)
	}
	return out, nil
}

// matches returns one match for each call that matches a signature
// condition in the call graph of a file.
func matches(matcher *callgraph.SignatureMatcher, cg *callgraph.CallGraph) ([]Match, error) {
	results, err := matcher.MatchSignatures(cg)
	if err != nil || len(results) == 0 {
		return nil, err
	}
	data, err := cg.Tree.Data()
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, r := range results {
		sig := signatureOf(r.MatchedSignature)
		for _, c := range r.MatchedConditions {
			for _, ev := range c.Evidences {
				md := ev.Metadata(data)
				m := Match{Signature: sig, FilePath: r.FilePath, Language: string(r.MatchedLanguageCode), Callee: md.CalleeNamespace}
				if at := md.CallerIdentifierMetadata; at != nil {
					m.Line, m.Column = int(at.StartLine)+1, int(at.StartColumn)+1
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

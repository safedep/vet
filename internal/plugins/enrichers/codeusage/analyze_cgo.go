//go:build cgo

package codeusage

import (
	"context"
	"fmt"
	"regexp"

	"github.com/safedep/code/core"
	"github.com/safedep/code/fs"
	"github.com/safedep/code/lang"
	"github.com/safedep/code/parser"
	"github.com/safedep/code/plugin"
	"github.com/safedep/code/plugin/depsusage"
)

// skipped are the directories that hold installed or built code, not the
// code of the project.
var skipped = []*regexp.Regexp{
	regexp.MustCompile(`(^|/)(node_modules|vendor|\.git|\.venv|venv|dist|build|target|__pycache__)(/|$)`),
}

// defaultAnalyzer parses the source files with tree-sitter, which needs
// CGO.
func defaultAnalyzer(ctx context.Context, dir string) ([]Evidence, error) {
	langs, err := lang.AllLanguages()
	if err != nil {
		return nil, err
	}
	fileSystem, err := fs.NewLocalFileSystem(fs.LocalFileSystemConfig{AppDirectories: []string{dir}, ExcludePatterns: skipped})
	if err != nil {
		return nil, err
	}
	walker, err := fs.NewSourceWalker(fs.SourceWalkerConfig{}, langs)
	if err != nil {
		return nil, err
	}
	tree, err := parser.NewWalkingParser(walker, langs)
	if err != nil {
		return nil, err
	}
	var out []Evidence
	var collect depsusage.DependencyUsageCallback = func(_ context.Context, ev *depsusage.UsageEvidence) error {
		out = append(out, Evidence{PackageHint: ev.PackageHint, ModuleName: ev.ModuleName, FilePath: ev.FilePath, Line: ev.Line})
		return nil
	}
	exec, err := plugin.NewTreeWalkPluginExecutor(tree, []core.Plugin{depsusage.NewDependencyUsagePlugin(collect)})
	if err != nil {
		return nil, err
	}
	if err := exec.Execute(ctx, fileSystem); err != nil {
		return nil, fmt.Errorf("code usage: %w", err)
	}
	return out, nil
}

// Available reports that this build has code analysis.
func Available() bool { return true }

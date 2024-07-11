package code

import (
	"github.com/safedep/vet/pkg/code/nodes"
)

// Declarative metadata for the source language
type SourceLanguageMeta struct {
	SourceFileGlobs []string
}

// Any source language implementation must support these
// primitives for integration with the code analysis system
type SourceLanguage interface {
	// Get metadata for the source language
	GetMeta() SourceLanguageMeta

	// Parse a source file and return the CST (tree-sitter concrete syntax tree)
	ParseSource(file SourceFile) (*nodes.CST, error)

	// Get import nodes from the CST
	GetImportNodes(cst *nodes.CST) ([]nodes.CSTImportNode, error)

	// Get function declaration nodes from the CST
	GetFunctionDeclarationNodes(cst *nodes.CST) ([]nodes.CSTFunctionNode, error)

	// Get function call nodes from the CST
	GetFunctionCallNodes(cst *nodes.CST) ([]nodes.CSTFunctionCallNode, error)

	// Resolve the import module / package name from relative path
	ResolveImportNameFromPath(relPath string) (string, error)

	// Resolve import name to possible relative file names
	// Multiple paths are possible because an import such
	// as a.b can resolve to a/b.py or a/b/__init__.py depending
	// on language and file system
	ResolveImportPathsFromName(currentFile SourceFile, importName string, includeImports bool) ([]string, error)
}

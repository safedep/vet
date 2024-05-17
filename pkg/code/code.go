package code

import (
	"context"
	"fmt"
	"io"

	sitter "github.com/smacker/go-tree-sitter"
)

// Things that we can do
// 1. Prune unused direct dependencies based on code usage
// 2. Find places in 1P code where a vulnerable library is imported
// 3. Find places in 1P code where a call to a vulnerable function is made
// 4. Find path from 1P code to a vulnerable function in direct or transitive dependencies
// 5. Find path from 1P code to a vulnerable library in direct or transitive dependencies

// Primitives that we need
// 1. Source code parsing
// 2. Import resolution to local 1P code or imported files in 3P code
// 3. Graph datastructure to represent a function call graph across 1P and 3P code
// 4. Graph datastructure to represent a file import graph across 1P and 3P code
//
// Source code parsing should provide
// 1. Enumerate imported 3P code
// 2. Enumerate functions in the source code
// 3. Enumerate function calls to 1P or 3P code
//
// Code Property Graph (CPG), stitching 1P and 3P code
// into a queryable graph datastructure for analyzers having
//
// Future enhancements should include ability to enrich function nodes
// with meta information such as contributors, last modified time, use-case tags etc.

// Represents a Concreate Syntax Tree (CST) of a *single* source file
// We will use TreeSitter as the only supported parser.
// However, we can have language specific wrappers over TreeSitter CST
// to make it easy for high level modules to operate
type CST struct {
	tree *sitter.Tree
	lang *sitter.Language
	code []byte
	file *SourceFile
}

type CSTImportNode struct {
	cst             *CST
	moduleNameNode  *sitter.Node
	moduleItemNode  *sitter.Node
	moduleAliasNode *sitter.Node
}

// Utilities for CSTImportNode
// The name of the imported module or package
func (n CSTImportNode) ImportName() string {
	if n.moduleNameNode != nil {
		return n.moduleNameNode.Content(n.cst.code)
	}

	return ""
}

// The item imported from the module or package
// Example: from abc import xyz
func (n CSTImportNode) ImportItem() string {
	if n.moduleItemNode != nil {
		return n.moduleItemNode.Content(n.cst.code)
	}

	return ""
}

// The alias used for the imported module or package
// Example: import abc as xyz
func (n CSTImportNode) ImportAlias() string {
	if n.moduleAliasNode != nil {
		return n.moduleAliasNode.Content(n.cst.code)
	}

	return ""
}

type CSTFunctionNode struct {
	cst  *CST
	node *sitter.Node
}

type CSTFunctionCallNode struct {
	cst      *CST
	receiver *sitter.Node
	callee   *sitter.Node
	args     *sitter.Node
}

func (n CSTFunctionCallNode) Receiver() string {
	if n.receiver != nil {
		return n.receiver.Content(n.cst.code)
	}

	return ""
}

func (n CSTFunctionCallNode) Callee() string {
	if n.callee != nil {
		return n.callee.Content(n.cst.code)
	}

	return ""
}

// CPG is created by merging CST, CFG, PDG and other graphs
// The CPG will likely be too big to be stored in memory. We will need
// a graph database adapter to store and query the CPG
type CPG interface {
	// Define the contracts for CPG
}

// Represents a source file. This is required because import resolution
// algorithm may need to know the path of the current file
type SourceFile struct {
	// Identifier for the source file. This is file depending on the
	// repository from where the file is retrieved. Local file path in case of
	// local file system as the repository
	Id string

	// The repository from where the source file is retrieved
	repository SourceRepository
}

func (f SourceFile) Open() (io.ReadCloser, error) {
	return f.repository.OpenSourceFile(f)
}

type sourceFileHandlerFn func(file SourceFile) error

// SourceRepository is a repository of source files. It can be a local
// repository such as a directory or a remote repository such as a git repository.
// The concept of repository is just to find 1P and 3P code while abstracting the
// underlying storage mechanism (e.g. local file system or remote git repository)
type SourceRepository interface {
	// Name of the repository
	Name() string

	// Enumerate all source files in the repository. This can be multiple
	// directories for a local source repository
	EnumerateSourceFiles(handler sourceFileHandlerFn) error

	// Get a source file by path. This function should enumerate all directories
	// available in the repository to check for existence of the source file by path
	GetSourceFileByPath(path string) (SourceFile, error)

	// Open a source file for reading
	OpenSourceFile(file SourceFile) (io.ReadCloser, error)

	// Configure the repository for a source language
	ConfigureForLanguage(language SourceLanguage)
}

// Declarative metadata for the source language
type SourceLanguageMeta struct {
	SourceFileGlobs []string
}

// Any source language implementation must support these
// primitives for integration with the code analysis system
// TODO: Apply ISP to separate out the interfaces by functionality
type SourceLanguage interface {
	GetMeta() SourceLanguageMeta
	ParseSource(file SourceFile) (*CST, error)
	GetImportNodes(cst *CST) ([]CSTImportNode, error)
	GetFunctionDeclarationNodes(cst *CST) ([]CSTFunctionNode, error)
	GetFunctionCallNodes(cst *CST) ([]CSTFunctionCallNode, error)
	ResolveImportPath(currentFile SourceFile, importName string) (SourceFile, error)
}

// Base implementation of a common source language
type commonSourceLanguage struct {
	parser *sitter.Parser
	lang   *sitter.Language
}

func (l *commonSourceLanguage) ParseSource(file SourceFile) (*CST, error) {
	fileReader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}

	defer fileReader.Close()

	data, err := io.ReadAll(fileReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read source: %w", err)
	}

	tree, err := l.parser.ParseCtx(context.Background(), nil, data)
	if err != nil {
		return nil, err
	}

	return &CST{tree: tree, lang: l.lang, file: &file, code: data}, nil
}

func (l *commonSourceLanguage) GetImportNodes(cst *CST) ([]CSTImportNode, error) {
	return nil, fmt.Errorf("language does not support import nodes")
}

func (l *commonSourceLanguage) GetFunctionDeclarationNodes(cst *CST) ([]CSTFunctionNode, error) {
	return nil, fmt.Errorf("language does not support function declaration nodes")
}

func (l *commonSourceLanguage) GetFunctionCallNodes(cst *CST) ([]CSTFunctionCallNode, error) {
	return nil, fmt.Errorf("language does not support function call nodes")
}

func (l *commonSourceLanguage) ResolveImportPath(currentFile SourceFile, importName string) (SourceFile, error) {
	return SourceFile{}, fmt.Errorf("language does not support import resolution")
}

func (l *commonSourceLanguage) GetMeta() SourceLanguageMeta {
	return SourceLanguageMeta{}
}

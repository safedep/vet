package code

import (
	"sync"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage/graph"
)

type CpgBuilderConfig struct {
	// Repository containing source files
	Repository SourceRepository

	// Language to use for parsing source files
	Language SourceLanguage

	// Resolve imports to file and load them
	RecursiveImport bool

	// Graph storage adapter
	Graph graph.Graph

	// Code analyser concurrency
	Concurrency int
}

type cpgBuilder struct {
	config CpgBuilderConfig

	// Building is a heavy operation, we will cache the CPG
	// on successful build
	cpg CPG

	// Queue for processing files
	fileQueue         chan SourceFile
	fileQueueWg       *sync.WaitGroup
	fileQueueLock     *sync.Mutex
	fileCache         map[string]bool
	functionCallCache map[string]string
}

// First attempt in building a CPG. Lets hardcode the intention
// within the name as a constant reminder to keep it simple and avoid
// generalization. We will not try to achieve building a full CPG (AST + CFG + PDG)
// but will use it as an inspiration to model entity relationships as a property graph.
type cpgSimple struct {
	graph graph.Graph
}

const (
	pkgNodeType   = "package"
	pkgNodeTypeFn = "functionDecl"
	pkgNodeTypeFc = "functionCall"

	pkgNodePropType     = "type"
	pkgNodePropFilePath = "path"

	pkgNodePropSource          = "source"
	pkgNodePropSourceValApp    = "app"
	pkgNodePropSourceValImport = "import"

	pkgRelationImport           = "IMPORTS"
	pkgRelationDeclaresFunction = "DECLARES"
	pkgRelationCallsFunction    = "CALLS"
)

type packageNode struct {
	id    string
	name  string
	props map[string]string
}

type functionNode struct {
	id    string
	name  string
	props map[string]string
}

type functionCallNode struct {
	id    string
	name  string
	props map[string]string
}

// Build a graph relationship between two package nodes
func (n *packageNode) Imports(anotherNode *packageNode) *graph.Edge {
	logger.Debugf("Creating edge from %s to %s", n.id, anotherNode.id)

	return &graph.Edge{
		Name: pkgRelationImport,
		From: &graph.Node{
			ID:         n.id,
			Label:      pkgNodeType,
			Properties: n.props,
		},
		To: &graph.Node{
			ID:         anotherNode.id,
			Label:      pkgNodeType,
			Properties: anotherNode.props,
		},
	}
}

func (n *packageNode) DeclaresFunction(fn *functionNode) *graph.Edge {
	logger.Debugf("Creating edge from %s to %s", n.id, fn.id)

	return &graph.Edge{
		Name: pkgRelationDeclaresFunction,
		From: &graph.Node{
			ID:         n.id,
			Label:      pkgNodeType,
			Properties: n.props,
		},
		To: &graph.Node{
			ID:         fn.id,
			Label:      pkgNodeTypeFn,
			Properties: fn.props,
		},
	}
}

func (n *packageNode) CallsFunction(fn *functionCallNode) *graph.Edge {
	logger.Debugf("Creating edge from %s to %s", n.id, fn.id)

	return &graph.Edge{
		Name: pkgRelationCallsFunction,
		From: &graph.Node{
			ID:         n.id,
			Label:      pkgNodeType,
			Properties: n.props,
		},
		To: &graph.Node{
			ID:         fn.id,
			Label:      pkgNodeTypeFc,
			Properties: fn.props,
		},
	}
}

func NewCpgBuilder(config CpgBuilderConfig) (*cpgBuilder, error) {
	// Concurrency will cause issues with the the common cache
	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}

	return &cpgBuilder{config: config}, nil
}

// The CPG build will use the source repository to enumerate all source files,
// parse them using the source language and build a CPG. The algorithm to build
// a CPG resides here. Common queries on the CPG are implemented within the CPG
// implementation itself.
func (b *cpgBuilder) Build() (CPG, error) {
	if b.cpg != nil {
		logger.Debugf("Using cached CPG")
		return b.cpg, nil
	}

	// Reinitialize the file queue if needed
	if b.fileQueue != nil {
		close(b.fileQueue)
	}

	b.fileQueue = make(chan SourceFile, 10000)
	b.fileQueueWg = &sync.WaitGroup{}
	b.fileQueueLock = &sync.Mutex{}

	b.fileCache = make(map[string]bool)
	b.functionCallCache = make(map[string]string)

	cpg := &cpgSimple{graph: b.config.Graph}
	logger.Debugf("Building CPG using repository: %s", b.config.Repository.Name())

	// Start the file processors as a separate goroutine
	for i := 0; i < b.config.Concurrency; i++ {
		go b.fileProcessor(b.fileQueueWg)
	}

	err := b.config.Repository.EnumerateSourceFiles(func(file SourceFile) error {
		b.enqueueSourceFile(file)
		return nil
	})

	b.fileQueueWg.Wait()

	close(b.fileQueue)
	b.fileQueue = nil

	if err != nil {
		return nil, err
	}

	b.cpg = cpg
	return cpg, nil
}

func (b *cpgBuilder) enqueueSourceFile(file SourceFile) {
	b.fileQueueLock.Lock()
	defer b.fileQueueLock.Unlock()

	if _, ok := b.fileCache[file.Path]; ok {
		logger.Debugf("Skipping already processed file: %s", file.Path)
		return
	}

	b.fileQueueWg.Add(1)
	b.fileQueue <- file

	// TODO: Optimize this. Storing entire file path is not needed
	b.fileCache[file.Path] = true
}

func (b *cpgBuilder) fileProcessor(wg *sync.WaitGroup) {
	for file := range b.fileQueue {
		err := b.buildForFile(file)
		if err != nil {
			logger.Errorf("Failed to process CPG for: %s: %v", file.Path, err)
		}

		wg.Done()
	}
}

func (b *cpgBuilder) buildForFile(file SourceFile) error {
	logger.Debugf("Parsing source file: %s", file.Path)

	cst, err := b.config.Language.ParseSource(file)
	if err != nil {
		return err
	}

	defer cst.tree.Close()

	b.processSourceFileNode(b.config.Graph, file)
	b.processImportNodes(b.config.Graph, cst, b.config.Language, file)
	b.processFunctionDeclarations(b.config.Graph, cst, b.config.Language, file)
	b.processFunctionCalls(b.config.Graph, cst, b.config.Language, file)

	return nil
}

func (b *cpgBuilder) processSourceFileNode(g graph.Graph, file SourceFile) {
	// What?
}

func (b *cpgBuilder) processImportNodes(g graph.Graph, cst *CST, lang SourceLanguage,
	currentFile SourceFile) {
	// Get the module name for the source file we are processing
	// This serves as the current node in the graph
	currentModuleName, err := langMapFileToModule(currentFile, b.config.Repository, lang, true)
	if err != nil {
		logger.Errorf("Failed to map file to module: %v", err)
		return
	}

	thisNode := b.buildPackageNode(currentModuleName,
		currentModuleName, currentFile.Path, b.importSourceName(currentFile))

	importNodes, err := lang.GetImportNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get import nodes: %v", err)
		return
	}

	for _, importNode := range importNodes {
		logger.Debugf("Processing import node: %s", importNode.ImportName())

		// Try to resolve the imported package to file for further processing
		sourceFile, err := langMapModuleToFile(importNode.ImportName(), currentFile,
			b.config.Repository, lang, true)
		if err != nil {
			logger.Warnf("Failed to process import node: %s: %v", importNode.ImportName(), err)
		} else {
			logger.Debugf("Import node: %s resolved to path: %s",
				importNode.ImportName(), sourceFile.Path)

			if b.useImports() {
				b.enqueueSourceFile(sourceFile)
			}
		}

		// Import name may be current file relative in which case we fix it up
		// to appropriate module name to avoid duplicate nodes in the graph
		importNodeName := importNode.ImportName()
		if len(sourceFile.Path) > 0 {
			fixedImportName, err := langMapFileToModule(sourceFile, b.config.Repository, lang, true)
			if err != nil {
				logger.Errorf("[Import Fixing]: Failed to map file to module: %v", err)
				return
			} else {
				importNodeName = fixedImportName
			}
		}

		// Finally add the imported package node to the graph
		importedPkgNode := b.buildPackageNode(importNodeName, importNodeName,
			sourceFile.Path, b.importSourceName(sourceFile))

		err = g.Link(thisNode.Imports(&importedPkgNode))
		if err != nil {
			logger.Errorf("Failed to link import node: %v", err)
		}
	}
}

func (b *cpgBuilder) processFunctionDeclarations(g graph.Graph, cst *CST, lang SourceLanguage,
	currentFile SourceFile) {
	moduleName, err := langMapFileToModule(currentFile, b.config.Repository, lang, true)
	if err != nil {
		logger.Errorf("Failed to map file to module: %v", err)
		return
	}

	functionDecls, err := lang.GetFunctionDeclarationNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get function declaration nodes: %v", err)
		return
	}

	thisNode := b.buildPackageNode(moduleName, moduleName,
		currentFile.Path, b.importSourceName(currentFile))

	for _, functionDecl := range functionDecls {
		logger.Debugf("Processing function declaration: %s/%s",
			moduleName,
			functionDecl.Name())

		fnNode := functionNode{
			id:   functionDecl.Name(),
			name: functionDecl.Name(),
			props: map[string]string{
				pkgNodePropFilePath: currentFile.Path,
				pkgNodePropType:     pkgNodeTypeFn,
				pkgNodePropSource:   b.importSourceName(currentFile),
			},
		}

		err = g.Link(thisNode.DeclaresFunction(&fnNode))
		if err != nil {
			logger.Errorf("Failed to link function declaration: %v", err)
		}
	}
}

// The function call graph will be built as follows:
// [Function] -> [FunctionCall] -> [Function]
//
// # To build this, we will
//
// - Enumerate all function declarations
// - Assign an unique ID for the function (source)
// - Enumerate all function calls within the function body
// - Resolve the function call to a function declaration
// - Assign an unique ID to the called function (target)
// - Store the relationship in the graph
//
// We make a trade-off here. We are not able to capture the
// the function calls that are outside the scope of a function
func (b *cpgBuilder) processFunctionCalls(g graph.Graph, cst *CST, lang SourceLanguage,
	currentFile SourceFile) {
	moduleName, err := langMapFileToModule(currentFile, b.config.Repository, lang, true)
	if err != nil {
		logger.Errorf("Failed to map file to module: %v", err)
		return
	}

	thisNode := b.buildPackageNode(moduleName, moduleName,
		currentFile.Path, b.importSourceName(currentFile))

	functionCalls, err := lang.GetFunctionCallNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get function call nodes: %v", err)
		return
	}

	for _, functionCall := range functionCalls {
		if c, ok := b.functionCallCache[moduleName]; ok {
			if c == functionCall.Callee() {
				continue
			}
		}

		logger.Debugf("Processing function call: %s", functionCall.Callee())

		fnCallNode := functionCallNode{
			id:   functionCall.Callee(),
			name: functionCall.Callee(),
			props: map[string]string{
				pkgNodePropFilePath: currentFile.Path,
				pkgNodePropType:     pkgNodeTypeFc,
				pkgNodePropSource:   b.importSourceName(currentFile),
			},
		}

		err = g.Link(thisNode.CallsFunction(&fnCallNode))
		if err != nil {
			logger.Errorf("Failed to link function call: %v", err)
		}

		b.functionCallCache[moduleName] = functionCall.Callee()
	}
}

func (b *cpgBuilder) useImports() bool {
	return b.config.RecursiveImport
}

func (b *cpgBuilder) buildPackageNode(id, name, path, src string) packageNode {
	return packageNode{
		id:   id,
		name: name,
		props: map[string]string{
			pkgNodePropFilePath: path,
			pkgNodePropType:     pkgNodeType,
			pkgNodePropSource:   src,
		},
	}
}

func (b *cpgBuilder) importSourceName(file SourceFile) string {
	if file.IsImportedFile() {
		return pkgNodePropSourceValImport
	} else {
		return pkgNodePropSourceValApp
	}
}

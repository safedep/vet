package code

import (
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage/graph"
)

type CpgBuilderConfig struct {
	Repository SourceRepository
	Language   SourceLanguage
	Graph      graph.Graph
}

type cpgBuilder struct {
	config CpgBuilderConfig

	// Building is a heavy operation, we will cache the CPG
	// on successful build
	cpg CPG
}

// Per file local scratch pad (state) for building the CPG
type cpgBuilderLocalScratchPad struct {
	imports       []CSTImportNode
	functionCalls []CSTFunctionCallNode
}

// First attempt in building a CPG. Lets hardcode the intention
// within the name as a constant reminder to keep it simple and avoid
// generalization. We will not try to achieve building a full CPG (AST + CFG + PDG)
// but will use it as an inspiration to model entity relationships as a property graph.
type cpgSimple struct {
	graph graph.Graph
}

const (
	pkgNodeType           = "package"
	pkgNodeImportRelation = "imports"
)

type packageNode struct {
	id    string
	name  string
	props map[string]string
}

// Build a graph relationship between two package nodes
func (n *packageNode) Imports(anotherNode *packageNode) *graph.Edge {
	logger.Debugf("Creating edge from %s to %s", n.id, anotherNode.id)

	return &graph.Edge{
		Name: pkgNodeImportRelation,
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

func NewCpgBuilder(config CpgBuilderConfig) (*cpgBuilder, error) {
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

	cpg := &cpgSimple{graph: b.config.Graph}
	logger.Debugf("Building CPG using repository: %s", b.config.Repository.Name())

	// TODO: May be we need a go channel approach for processing because
	// we need to enqueue more source files from imported packages

	err := b.config.Repository.EnumerateSourceFiles(func(file SourceFile) error {
		logger.Debugf("Parsing source file: %s", file.Id)

		cst, err := b.config.Language.ParseSource(file)
		if err != nil {
			return err
		}

		scratchPad := &cpgBuilderLocalScratchPad{
			imports: make([]CSTImportNode, 0),
		}

		b.processSourceFileNode(b.config.Graph, file)
		b.processImportNodes(b.config.Graph, cst, b.config.Language, scratchPad, file)
		b.processFunctionCalls(b.config.Graph, cst, b.config.Language, scratchPad, file)

		return nil
	})

	if err != nil {
		return nil, err
	}

	b.cpg = cpg
	return cpg, nil
}

func (b *cpgBuilder) processSourceFileNode(g graph.Graph, file SourceFile) {
	// What?
}

func (b *cpgBuilder) processImportNodes(g graph.Graph, cst *CST, lang SourceLanguage,
	scratch *cpgBuilderLocalScratchPad,
	currentFile SourceFile) {

	relativeSourceFilePath, err := b.config.Repository.GetRelativePath(currentFile.Id, true)
	if err != nil {
		logger.Errorf("Failed to get relative path for current file: %v", err)
		return
	}

	currentModuleName, err := lang.ResolveImportNameFromPath(relativeSourceFilePath)
	if err != nil {
		logger.Errorf("Failed to resolve import name from path: %v", err)
		return
	}

	// We will use the strategy of resolving the import module name from
	// the source relative file path. This import module name will be used
	// for uniquely identifying the package node in the graph. There are possibility
	// of conflict across different import paths but we will ignore that for now.

	thisNode := &packageNode{
		id:    currentModuleName,
		name:  relativeSourceFilePath,
		props: map[string]string{"path": currentFile.Id},
	}

	importNodes, err := lang.GetImportNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get import nodes: %v", err)
		return
	}

	for _, importNode := range importNodes {
		logger.Debugf("Processing import node: %s", importNode.ImportName())

		/*
			importedFilePaths, err := lang.ResolveImportPathsFromName(importNode.ImportName())
			if err != nil {
				logger.Errorf("Failed to resolve import paths from name: %v", err)
				continue
			}
		*/

		importedPkgNode := &packageNode{
			id:   importNode.ImportName(),
			name: importNode.ImportName(),
			props: map[string]string{
				"item":  importNode.ImportItem(),
				"alias": importNode.ImportAlias(),
			},
		}

		err = g.Link(thisNode.Imports(importedPkgNode))
		if err != nil {
			logger.Errorf("Failed to link import node: %v", err)
		}

		scratch.imports = append(scratch.imports, importNode)
	}
}

func (b *cpgBuilder) processFunctionCalls(_ graph.Graph, cst *CST, lang SourceLanguage,
	scratch *cpgBuilderLocalScratchPad,
	_ SourceFile) {
	functionCallNodes, err := lang.GetFunctionCallNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get function call nodes: %v", err)
		return
	}

	for _, functionCallNode := range functionCallNodes {
		logger.Debugf("Processing function call node: %s", functionCallNode.Callee())
	}

	scratch.functionCalls = append(scratch.functionCalls, functionCallNodes...)
}

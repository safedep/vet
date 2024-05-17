package code

import (
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage/graph"
)

type CpgBuilderConfig struct {
	Repository   SourceRepository
	Language     SourceLanguage
	DatabasePath string
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
// generalization.
type cpgSimple struct {
	graph graph.Graph
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

	graph, err := graph.NewPropertyGraph(&graph.LocalPropertyGraphConfig{
		Name:         "cpg",
		DatabasePath: b.config.DatabasePath,
	})

	if err != nil {
		return nil, err
	}

	cpg := &cpgSimple{graph: graph}
	logger.Debugf("Building CPG using repository: %s", b.config.Repository.Name())

	err = b.config.Repository.EnumerateSourceFiles(func(file SourceFile) error {
		logger.Debugf("Parsing source file: %s", file.Id)

		cst, err := b.config.Language.ParseSource(file)
		if err != nil {
			return err
		}

		scratchPad := &cpgBuilderLocalScratchPad{
			imports: make([]CSTImportNode, 0),
		}

		b.processSourceFileNode(graph, file)
		b.processImportNodes(graph, cst, b.config.Language, scratchPad, file)
		b.processFunctionCalls(graph, cst, b.config.Language, scratchPad, file)

		return nil
	})

	if err != nil {
		return nil, err
	}

	b.cpg = cpg
	return cpg, nil
}

func (b *cpgBuilder) processSourceFileNode(g graph.Graph, file SourceFile) {
	err := g.Link(&graph.Edge{
		Name: "contains",
		From: &graph.Node{
			ID:         file.repository.Name(),
			Label:      "repository",
			Properties: map[string]string{"name": file.repository.Name()},
		},
		To: &graph.Node{
			ID:         file.Id,
			Label:      "source_file",
			Properties: map[string]string{"path": file.Id},
		},
	})

	if err != nil {
		logger.Errorf("Failed to link source file node: %v", err)
	}
}

func (b *cpgBuilder) processImportNodes(g graph.Graph, cst *CST, lang SourceLanguage,
	scratch *cpgBuilderLocalScratchPad,
	currentFile SourceFile) {
	importNodes, err := lang.GetImportNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get import nodes: %v", err)
		return
	}

	for _, importNode := range importNodes {
		logger.Debugf("Processing import node: %s", importNode.ImportName())
		logger.Debugf("Adding edge from %s to %s", currentFile.Id, importNode.ImportName())

		// Source file has imports
		err := g.Link(&graph.Edge{
			Name: "imports",
			From: &graph.Node{
				ID:         currentFile.Id,
				Label:      "source_file",
				Properties: map[string]string{"path": currentFile.Id},
			},
			To: &graph.Node{
				ID:    importNode.ImportName(),
				Label: "imported_package",
				Properties: map[string]string{
					"name":  importNode.ImportName(),
					"item":  importNode.ImportItem(),
					"alias": importNode.ImportAlias(),
				},
			},
		})

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

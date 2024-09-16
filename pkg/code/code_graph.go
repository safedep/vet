package code

import (
	"sync"

	"github.com/safedep/vet/pkg/code/entities"
	"github.com/safedep/vet/pkg/code/nodes"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage/graph"
)

type CodeGraphBuilderConfig struct {
	// Resolve imports to file and load them
	RecursiveImport bool

	// Code analyser concurrency
	Concurrency int
}

type CodeGraphBuilderMetrics struct {
	GoRoutineCount int
	ErrorCount     int
	FilesProcessed int
	FilesInQueue   int
	ImportsCount   int
	FunctionsCount int
}

type CodeGraphBuilderEvent struct {
	Kind string
	Data interface{}
}

const (
	CodeGraphBuilderEventFileQueued        = "file_queued"
	CodeGraphBuilderEventFileProcessed     = "file_processed"
	CodeGraphBuilderEventImportProcessed   = "import_processed"
	CodeGraphBuilderEventFunctionProcessed = "function_processed"
)

// The event handler is invoked from its own go routine. Handler functions
// must be thread safe.
type CodeGraphBuilderEventHandler func(CodeGraphBuilderEvent, CodeGraphBuilderMetrics) error

type codeGraphBuilder struct {
	config        CodeGraphBuilderConfig
	eventHandlers map[string]CodeGraphBuilderEventHandler
	metrics       CodeGraphBuilderMetrics

	repository SourceRepository
	lang       SourceLanguage
	storage    graph.Graph

	// Queue for processing files
	fileQueue     chan SourceFile
	fileQueueWg   *sync.WaitGroup
	fileQueueLock *sync.Mutex

	fileCache         map[string]bool
	functionDeclCache map[string]string
	functionCallCache map[string]string
}

func NewCodeGraphBuilder(config CodeGraphBuilderConfig,
	repository SourceRepository,
	lang SourceLanguage,
	storage graph.Graph) (*codeGraphBuilder, error) {
	// Concurrency will cause issues with the the common cache
	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}

	return &codeGraphBuilder{
		config:        config,
		repository:    repository,
		lang:          lang,
		storage:       storage,
		eventHandlers: make(map[string]CodeGraphBuilderEventHandler, 0),
		metrics:       CodeGraphBuilderMetrics{GoRoutineCount: config.Concurrency},
	}, nil
}

func (b *codeGraphBuilder) RegisterEventHandler(name string, handler CodeGraphBuilderEventHandler) {
	if _, ok := b.eventHandlers[name]; ok {
		logger.Warnf("Event handler already registered: %s", name)
		return
	}

	b.eventHandlers[name] = handler
}

func (b *codeGraphBuilder) Build() error {
	// Reinitialize the file queue if needed
	if b.fileQueue != nil {
		close(b.fileQueue)
	}

	b.fileQueue = make(chan SourceFile, 10000)
	b.fileQueueWg = &sync.WaitGroup{}
	b.fileQueueLock = &sync.Mutex{}

	b.fileCache = make(map[string]bool)
	b.functionDeclCache = make(map[string]string)
	b.functionCallCache = make(map[string]string)

	logger.Debugf("Building code graph using repository: %s", b.repository.Name())

	for i := 0; i < b.config.Concurrency; i++ {
		go b.fileProcessor(b.fileQueueWg)
	}

	err := b.repository.EnumerateSourceFiles(func(file SourceFile) error {
		b.enqueueSourceFile(file)
		return nil
	})

	b.fileQueueWg.Wait()

	close(b.fileQueue)
	b.fileQueue = nil

	return err
}

func (b *codeGraphBuilder) enqueueSourceFile(file SourceFile) {
	b.synchronized(func() {
		b.metrics.FilesInQueue++

		if _, ok := b.fileCache[file.Path]; ok {
			logger.Debugf("Skipping already processed file: %s", file.Path)
			return
		}

		b.fileQueueWg.Add(1)
		b.fileQueue <- file

		// TODO: Optimize this. Storing entire file path is not needed
		b.fileCache[file.Path] = true
	})

	b.notifyEventHandlers(CodeGraphBuilderEvent{
		Kind: CodeGraphBuilderEventFileQueued,
		Data: file,
	}, b.metrics)
}

func (b *codeGraphBuilder) fileProcessor(wg *sync.WaitGroup) {
	for file := range b.fileQueue {
		err := b.buildForFile(file)
		if err != nil {
			logger.Errorf("Failed to process code graph for: %s: %v", file.Path, err)

			b.synchronized(func() {
				b.metrics.ErrorCount++
			})
		}

		wg.Done()

		b.synchronized(func() {
			b.metrics.FilesProcessed++
		})

		b.notifyEventHandlers(CodeGraphBuilderEvent{
			Kind: CodeGraphBuilderEventFileProcessed,
			Data: file,
		}, b.metrics)
	}
}

func (b *codeGraphBuilder) buildForFile(file SourceFile) error {
	logger.Debugf("Parsing source file: %s", file.Path)

	cst, err := b.lang.ParseSource(file)
	if err != nil {
		return err
	}

	defer cst.Close()

	b.processSourceFileNode(file)
	b.processImportNodes(cst, file)
	b.processFunctionDeclarations(cst, file)
	b.processFunctionCalls(cst, file)

	return nil
}

func (b *codeGraphBuilder) processSourceFileNode(file SourceFile) {
	// What?
}

func (b *codeGraphBuilder) processImportNodes(cst *nodes.CST, currentFile SourceFile) {
	// Get the module name for the source file we are processing
	// This serves as the current node in the graph
	currentModuleName, err := LangMapFileToModule(currentFile, b.repository, b.lang, b.useImports())
	if err != nil {
		logger.Errorf("Failed to map file to module: %v", err)
		return
	}

	thisNode := b.buildPackageNode(currentModuleName,
		currentModuleName, currentFile.Path, b.importSourceName(currentFile))

	importNodes, err := b.lang.GetImportNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get import nodes: %v", err)
		return
	}

	for _, importNode := range importNodes {
		logger.Debugf("Processing import node: %s", importNode.ImportName())

		// Try to resolve the imported package to file for further processing
		sourceFile, err := LangMapModuleToFile(importNode.ImportName(), currentFile,
			b.repository, b.lang, b.useImports())
		if err != nil {
			logger.Warnf("Failed to map import node: '%s' to file: %v", importNode.ImportName(), err)
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
			fixedImportName, err := LangMapFileToModule(sourceFile, b.repository, b.lang, b.useImports())
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

		err = b.storage.Link(thisNode.Imports(&importedPkgNode))
		if err != nil {
			logger.Errorf("Failed to link import node: %v", err)
		}

		b.synchronized(func() {
			b.metrics.ImportsCount++
		})

		b.notifyEventHandlers(CodeGraphBuilderEvent{
			Kind: CodeGraphBuilderEventImportProcessed,
			Data: importNode.ImportName(),
		}, b.metrics)
	}
}

func (b *codeGraphBuilder) processFunctionDeclarations(cst *nodes.CST, currentFile SourceFile) {
	moduleName, err := LangMapFileToModule(currentFile, b.repository, b.lang, b.useImports())
	if err != nil {
		logger.Errorf("Failed to map file to module: %v", err)
		return
	}

	functionDecls, err := b.lang.GetFunctionDeclarationNodes(cst)
	if err != nil {
		logger.Errorf("Failed to get function declaration nodes: %v", err)
		return
	}

	thisNode := b.buildPackageNode(moduleName, moduleName,
		currentFile.Path, b.importSourceName(currentFile))

	for _, functionDecl := range functionDecls {
		if fid, ok := b.functionDeclCache[moduleName]; ok {
			if fid == functionDecl.Id() {
				continue
			}
		}

		logger.Debugf("Processing function declaration: %s/%s",
			moduleName,
			functionDecl.Id())

		fnNode := entities.FunctionDecl{
			Id:             functionDecl.Id(),
			SourceFilePath: currentFile.Path,
			SourceFileType: b.importSourceName(currentFile),
			FunctionName:   functionDecl.Name(),
			ContainerName:  functionDecl.Container(),
		}

		err = b.storage.Link(thisNode.DeclaresFunction(&fnNode))
		if err != nil {
			logger.Errorf("Failed to link function declaration: %v", err)
		}

		b.synchronized(func() {
			b.metrics.FunctionsCount++
		})

		b.notifyEventHandlers(CodeGraphBuilderEvent{
			Kind: CodeGraphBuilderEventFunctionProcessed,
			Data: functionDecl.Id(),
		}, b.metrics)

		b.functionDeclCache[moduleName] = functionDecl.Id()
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
func (b *codeGraphBuilder) processFunctionCalls(cst *nodes.CST, currentFile SourceFile) {
	// Building a function call graph through static analysis is harder than expected
}

func (b *codeGraphBuilder) useImports() bool {
	return b.config.RecursiveImport
}

func (b *codeGraphBuilder) buildPackageNode(id, name, path, src string) entities.Package {
	return entities.Package{
		Id:             id,
		Name:           name,
		SourceFilePath: path,
		SourceFileType: src,
	}
}

func (b *codeGraphBuilder) importSourceName(file SourceFile) string {
	if file.IsImportedFile() {
		return entities.PackageEntitySourceTypeImport
	} else {
		return entities.PackageEntitySourceTypeApp
	}
}

func (b *codeGraphBuilder) notifyEventHandlers(event CodeGraphBuilderEvent, metrics CodeGraphBuilderMetrics) {
	for name, handler := range b.eventHandlers {
		err := handler(event, metrics)
		if err != nil {
			logger.Warnf("Failed to notify event handler: %s: %v", name, err)
		}
	}
}

func (b *codeGraphBuilder) synchronized(fn func()) {
	b.fileQueueLock.Lock()
	defer b.fileQueueLock.Unlock()

	fn()
}

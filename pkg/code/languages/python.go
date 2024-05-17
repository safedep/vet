package languages

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/code/nodes"
	"github.com/safedep/vet/pkg/common/logger"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

type pythonSourceLanguage struct {
	commonSourceLanguage
}

func NewPythonSourceLanguage() (code.SourceLanguage, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())

	return &pythonSourceLanguage{
		commonSourceLanguage: commonSourceLanguage{
			parser: parser,
			lang:   python.GetLanguage(),
		},
	}, nil
}

func (l *pythonSourceLanguage) GetMeta() code.SourceLanguageMeta {
	return code.SourceLanguageMeta{
		SourceFileGlobs: []string{"*.py"},
	}
}

func (l *pythonSourceLanguage) GetImportNodes(cst *nodes.CST) ([]nodes.CSTImportNode, error) {
	// Tree Sitter query to get import nodes in Python
	// The order of capture names are important because the extraction
	// uses capture index
	query := `
	(import_statement
		name: ((dotted_name) @module_name))

	(import_from_statement
		module_name: (dotted_name) @module_name
		name: (dotted_name
			(identifier) @submodule_name @submodule_alias))

	(import_from_statement
		module_name: (relative_import) @module_name
		name: (dotted_name
			(identifier) @submodule_name @submodule_alias))

	(import_statement
		name: (aliased_import
			name: ((dotted_name) @module_name @submodule_name)
			alias: (identifier) @submodule_alias))

	(import_from_statement
		module_name: (dotted_name) @module_name
		name: (aliased_import
			name: (dotted_name
				(identifier) @submodule_name)
			 alias: (identifier) @submodule_alias))

	(import_from_statement
		module_name: (relative_import) @module_name
		name: (aliased_import
			name: ((dotted_name) @submodule_name)
			alias: (identifier) @submodule_alias))
	`

	importNodes := []nodes.CSTImportNode{}
	err := code.TSExecQuery(query, python.GetLanguage(),
		cst.Code(),
		cst.Root(),
		func(m *sitter.QueryMatch, _ *sitter.Query, ok bool) error {
			importNode := nodes.NewCSTImportNode(cst).
				WithModuleName(m.Captures[0].Node)

			if len(m.Captures) > 1 {
				importNode = importNode.WithModuleItem(m.Captures[1].Node)
			}

			if len(m.Captures) > 2 {
				importNode = importNode.WithModuleAlias(m.Captures[2].Node)
			}

			logger.Debugf("Found imported module: %s (%s) as (%s)",
				importNode.ImportName(),
				importNode.ImportItem(),
				importNode.ImportAlias())

			importNodes = append(importNodes, *importNode)

			return nil
		})

	return importNodes, err
}

func (l *pythonSourceLanguage) GetFunctionDeclarationNodes(cst *nodes.CST) ([]nodes.CSTFunctionNode, error) {
	query := `
	(function_definition
		name: (identifier) @function_name
		parameters: (parameters) @function_args
		body: (block) @function_body) @function_declaration
	`
	functionNodes := []nodes.CSTFunctionNode{}
	err := code.TSExecQuery(query, python.GetLanguage(),
		cst.Code(),
		cst.Root(),
		func(m *sitter.QueryMatch, _ *sitter.Query, ok bool) error {
			if len(m.Captures) != 4 {
				return fmt.Errorf("expected 4 captures, got %d", len(m.Captures))
			}

			functionNode := nodes.NewCSTFunctionNode(cst).
				WithDeclaration(m.Captures[0].Node).
				WithName(m.Captures[1].Node).
				WithArgs(m.Captures[2].Node).
				WithBody(m.Captures[3].Node)

			// Find the containing class if any by walking up the tree
			parent := functionNode.Declaration().Parent()
			for parent != nil {
				if parent.Type() == "class_definition" {
					functionNode = functionNode.WithContainer(parent.ChildByFieldName("name"))
					break
				}

				parent = parent.Parent()
			}

			logger.Debugf("Found function declaration: %s/%s",
				functionNode.Container(),
				functionNode.Name())

			functionNodes = append(functionNodes, *functionNode)
			return nil
		})

	return functionNodes, err
}

func (l *pythonSourceLanguage) GetFunctionCallNodes(cst *nodes.CST) ([]nodes.CSTFunctionCallNode, error) {
	query := `
	(call
		function: (identifier) @function_name
		arguments: (argument_list) @arguments) @function_call

	(call
		function: (attribute
			object: (identifier) @object
			attribute: (identifier) @function_name)
		arguments: (argument_list) @arguments) @function_call
	`
	callNodes := []nodes.CSTFunctionCallNode{}
	err := code.TSExecQuery(query, python.GetLanguage(),
		cst.Code(),
		cst.Root(),
		func(m *sitter.QueryMatch, q *sitter.Query, ok bool) error {
			if len(m.Captures) < 3 {
				return fmt.Errorf("expected at least 3 captures, got %d", len(m.Captures))
			}

			functionCallNode := nodes.NewCSTFunctionCallNode(cst).WithCall(m.Captures[0].Node)

			n := len(m.Captures)
			switch n {
			case 3:
				functionCallNode = functionCallNode.WithCallee(m.Captures[1].Node)
				functionCallNode = functionCallNode.WithArgs(m.Captures[2].Node)
			case 4:
				functionCallNode = functionCallNode.WithReceiver(m.Captures[1].Node)
				functionCallNode = functionCallNode.WithCallee(m.Captures[2].Node)
				functionCallNode = functionCallNode.WithArgs(m.Captures[3].Node)
			}

			logger.Debugf("Found function call: (%s).%s",
				functionCallNode.Receiver(),
				functionCallNode.Callee())

			callNodes = append(callNodes, *functionCallNode)
			return nil
		})

	return callNodes, err
}

func (l *pythonSourceLanguage) ResolveImportNameFromPath(relPath string) (string, error) {
	if relPath[0] == '/' {
		return "", fmt.Errorf("path is not relative: %s", relPath)
	}

	relPath = strings.TrimSuffix(relPath, "__init__.py")
	relPath = strings.TrimSuffix(relPath, "/")
	relPath = strings.TrimSuffix(relPath, ".py")

	relPath = strings.ReplaceAll(relPath, "/", ".")

	return relPath, nil
}

func (l *pythonSourceLanguage) ResolveImportPathsFromName(currentFile code.SourceFile,
	importName string, includeImports bool) ([]string, error) {
	paths := []string{}

	if len(importName) == 0 {
		return paths, fmt.Errorf("import name is empty")
	}

	// If its a relative import, resolve it to the root
	if importName[0] == '.' {
		currDir := filepath.Dir(currentFile.Path)
		relativeImportName := filepath.Join(currDir, importName[1:])

		rootRelativePath, err := currentFile.Repository().GetRelativePath(relativeImportName, includeImports)
		if err != nil {
			return paths, fmt.Errorf("failed to get relative path: %w", err)
		}

		importName = rootRelativePath
	}

	importName = strings.ReplaceAll(importName, ".", "/")

	paths = append(paths, importName+".py")
	paths = append(paths, importName+"/__init__.py")

	return paths, nil
}

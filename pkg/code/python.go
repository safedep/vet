package code

import (
	"fmt"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

type pythonSourceLanguage struct {
	commonSourceLanguage
}

func NewPythonSourceLanguage() (SourceLanguage, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())

	return &pythonSourceLanguage{
		commonSourceLanguage: commonSourceLanguage{
			parser: parser,
			lang:   python.GetLanguage(),
		},
	}, nil
}

func (l *pythonSourceLanguage) GetMeta() SourceLanguageMeta {
	return SourceLanguageMeta{
		SourceFileGlobs: []string{"*.py"},
	}
}

func (l *pythonSourceLanguage) GetImportNodes(cst *CST) ([]CSTImportNode, error) {
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

	nodes := []CSTImportNode{}
	err := tsExecQuery(query, python.GetLanguage(),
		cst.code,
		cst.tree.RootNode(),
		func(m *sitter.QueryMatch, _ *sitter.Query, ok bool) error {
			importNode := CSTImportNode{
				moduleNameNode: m.Captures[0].Node,
				cst:            cst,
			}

			if len(m.Captures) > 1 {
				importNode.moduleItemNode = m.Captures[1].Node
			}

			if len(m.Captures) > 2 {
				importNode.moduleAliasNode = m.Captures[2].Node
			}

			logger.Debugf("Found imported module: %s (%s) as (%s) in %s:%d",
				importNode.ImportName(),
				importNode.ImportItem(),
				importNode.ImportAlias(),
				importNode.cst.file.Path,
				importNode.moduleNameNode.StartPoint().Row)

			nodes = append(nodes, importNode)

			return nil
		})

	return nodes, err
}

func (l *pythonSourceLanguage) GetFunctionCallNodes(cst *CST) ([]CSTFunctionCallNode, error) {
	query := `
	(call
		function: (identifier) @function_name
		arguments: (argument_list) @arguments)

	(call
		function: (attribute
			object: (identifier) @object
			attribute: (identifier) @function_name)
		arguments: (argument_list) @arguments)
	`
	nodes := []CSTFunctionCallNode{}
	err := tsExecQuery(query, python.GetLanguage(),
		cst.code,
		cst.tree.RootNode(),
		func(m *sitter.QueryMatch, q *sitter.Query, ok bool) error {
			functionCallNode := CSTFunctionCallNode{cst: cst}

			n := len(m.Captures)
			switch n {
			case 2:
				functionCallNode.callee = m.Captures[0].Node
				functionCallNode.args = m.Captures[1].Node
			case 3:
				functionCallNode.receiver = m.Captures[0].Node
				functionCallNode.callee = m.Captures[1].Node
				functionCallNode.args = m.Captures[2].Node
			}

			logger.Debugf("Found function call: (%s).%s in %s:%d",
				functionCallNode.Receiver(),
				functionCallNode.Callee(),
				cst.file.Path,
				functionCallNode.callee.StartPoint().Row)

			nodes = append(nodes, functionCallNode)
			return nil
		})

	return nodes, err
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

func (l *pythonSourceLanguage) ResolveImportPathsFromName(importName string) ([]string, error) {
	paths := []string{}

	importName = strings.ReplaceAll(importName, ".", "/")

	paths = append(paths, importName+".py")
	paths = append(paths, importName+"/__init__.py")

	return paths, nil
}

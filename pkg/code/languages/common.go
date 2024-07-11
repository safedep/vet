package languages

import (
	"context"
	"fmt"
	"io"

	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/code/nodes"
	sitter "github.com/smacker/go-tree-sitter"
)

// Base implementation of a common source language
type commonSourceLanguage struct {
	parser *sitter.Parser
	lang   *sitter.Language
}

func (l *commonSourceLanguage) ParseSource(file code.SourceFile) (*nodes.CST, error) {
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

	return nodes.NewCST(tree, l.lang, data), nil
}

func (l *commonSourceLanguage) GetImportNodes(cst *nodes.CST) ([]nodes.CSTImportNode, error) {
	return nil, fmt.Errorf("language does not support import nodes")
}

func (l *commonSourceLanguage) GetFunctionDeclarationNodes(cst *nodes.CST) ([]nodes.CSTFunctionNode, error) {
	return nil, fmt.Errorf("language does not support function declaration nodes")
}

func (l *commonSourceLanguage) GetFunctionCallNodes(cst *nodes.CST) ([]nodes.CSTFunctionCallNode, error) {
	return nil, fmt.Errorf("language does not support function call nodes")
}

func (l *commonSourceLanguage) ResolveImportNameFromPath(relPath string) (string, error) {
	return "", fmt.Errorf("language does not support import name resolution")
}

func (l *commonSourceLanguage) ResolveImportPathsFromName(importName string) ([]string, error) {
	return nil, fmt.Errorf("language does not support import path resolution")
}

func (l *commonSourceLanguage) GetMeta() code.SourceLanguageMeta {
	return code.SourceLanguageMeta{}
}

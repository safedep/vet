package code

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

type tsQueryMatchHandler func(*sitter.QueryMatch, *sitter.Query, bool) error

func TSExecQuery(query string, lang *sitter.Language, source []byte,
	node *sitter.Node, handler tsQueryMatchHandler) error {
	tsQuery, err := sitter.NewQuery([]byte(query), lang)
	if err != nil {
		return err
	}

	tsQueryCursor := sitter.NewQueryCursor()
	tsQueryCursor.Exec(tsQuery, node)

	for {
		match, ok := tsQueryCursor.NextMatch()
		if !ok {
			break
		}

		match = tsQueryCursor.FilterPredicates(match, source)

		if len(match.Captures) == 0 {
			continue
		}

		if err := handler(match, tsQuery, ok); err != nil {
			return err
		}
	}

	return nil
}

// Maps a file path to a module name. This is an important operation
// because it serves as the bridge between FS and Language domain
func LangMapFileToModule(file SourceFile, repo SourceRepository, lang SourceLanguage, includeImports bool) (string, error) {
	// Get the relative path of the file in the repository because most language
	// runtimes (module loaders) identify modules by relative paths
	relSourceFilePath, err := repo.GetRelativePath(file.Path, includeImports)
	if err != nil {
		return "", fmt.Errorf("failed to get relative path: %w", err)
	}

	// Use the language adapter to translate the relative path to a module name
	// which is language specific
	moduleName, err := lang.ResolveImportNameFromPath(relSourceFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve import name from path: %w", err)
	}

	return moduleName, nil
}

// Maps a module name back to a file path that must exist in the repository
func LangMapModuleToFile(moduleName string, currentFile SourceFile,
	repo SourceRepository, lang SourceLanguage, includeImports bool) (SourceFile, error) {
	// Use the language adapter to get possible relative paths for the module name
	relPaths, err := lang.ResolveImportPathsFromName(currentFile, moduleName, includeImports)
	if err != nil {
		return SourceFile{}, fmt.Errorf("failed to resolve import paths from name: %w", err)
	}

	for _, relPath := range relPaths {
		sf, err := repo.GetSourceFileByPath(relPath, includeImports)
		if err != nil {
			continue
		} else {
			return sf, nil
		}
	}

	return SourceFile{}, fmt.Errorf("no source file found for module: %s", moduleName)
}

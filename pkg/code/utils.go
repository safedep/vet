package code

import "fmt"

// Maps a file path to a module name. This is an important operation
// because it serves as the bridge between FS and Language domain
func langMapFileToModule(path string, repo SourceRepository, lang SourceLanguage, includeImports bool) (string, error) {
	// Get the relative path of the file in the repository because most language
	// runtimes (module loaders) identify modules by relative paths
	relSourceFilePath, err := repo.GetRelativePath(path, includeImports)
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
func langMapModuleToFile(moduleName string, repo SourceRepository, lang SourceLanguage, includeImports bool) (string, error) {
	// Use the language adapter to get possible relative paths for the module name
	relPaths, err := lang.ResolveImportPathsFromName(moduleName)
	if err != nil {
		return "", fmt.Errorf("failed to resolve import paths from name: %w", err)
	}

	sourceFilePath := ""
	for _, relPath := range relPaths {
		sf, err := repo.GetSourceFileByPath(relPath, includeImports)
		if err != nil {
			continue
		} else {
			sourceFilePath = sf.Path
			break
		}
	}

	if sourceFilePath == "" {
		return "", fmt.Errorf("failed to map module to file: %s", moduleName)
	}

	return sourceFilePath, nil
}

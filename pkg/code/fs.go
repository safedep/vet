package code

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
)

type FileSystemSourceRepositoryConfig struct {
	// List of paths to search for source code
	SourcePaths []string

	// Glob patterns to exclude from source code search
	ExcludedGlobs []string

	// Glob patterns to include in source code search
	IncludedGlobs []string

	// List of paths to search for imported source code
	ImportPaths []string
}

type fileSystemSourceRepository struct {
	config FileSystemSourceRepositoryConfig
}

func NewFileSystemSourceRepository(config FileSystemSourceRepositoryConfig) (SourceRepository, error) {
	return &fileSystemSourceRepository{config: config}, nil
}

func (r *fileSystemSourceRepository) Name() string {
	return "FileSystemSourceRepository"
}

func (r *fileSystemSourceRepository) GetRelativePath(path string, includeImportPaths bool) (string, error) {
	lookupPaths := []string{}

	lookupPaths = append(lookupPaths, r.config.SourcePaths...)
	if includeImportPaths {
		lookupPaths = append(lookupPaths, r.config.ImportPaths...)
	}

	for _, rootPath := range lookupPaths {
		if relPath, err := filepath.Rel(rootPath, path); err == nil {
			if strings.HasPrefix(relPath, "..") {
				continue
			}

			return relPath, nil
		}
	}

	return "", fmt.Errorf("path not found in source or import paths: %s", path)
}

func (r *fileSystemSourceRepository) ConfigureForLanguage(language SourceLanguage) {
	langMeta := language.GetMeta()

	r.config.IncludedGlobs = append(r.config.IncludedGlobs, langMeta.SourceFileGlobs...)
}

func (r *fileSystemSourceRepository) EnumerateSourceFiles(handler sourceFileHandlerFn) error {
	logger.Debugf("Enumerating source files with config: %v", r.config)

	for _, sourcePath := range r.config.SourcePaths {
		if err := r.enumSourceDir(sourcePath, handler); err != nil {
			return err
		}
	}

	return nil
}

// GetSourceFileByPath searches for a source file by path in the repository.
// It starts by searching the source paths and then the import paths.
//
// TODO: This is a problem. Source file lookup is ecosystem specific. For example
// Python and Ruby may have different rules to lookup a source file by path during
// import operation. May be we need to make the operations explicit at repository level.
func (r *fileSystemSourceRepository) GetSourceFileByPath(path string, includeImports bool) (SourceFile, error) {
	lookupPaths := []string{}

	// Import paths are generally are higher precedence than source paths
	if includeImports {
		lookupPaths = append(lookupPaths, r.config.ImportPaths...)
	}

	lookupPaths = append(lookupPaths, r.config.SourcePaths...)

	for _, sourcePath := range lookupPaths {
		st, err := os.Stat(sourcePath)
		if err != nil {
			continue
		}

		if !st.IsDir() {
			continue
		}

		sourceFilePath := filepath.Join(sourcePath, path)
		if _, err := os.Stat(sourceFilePath); err == nil {
			return SourceFile{
				Path:       sourceFilePath,
				repository: r,
			}, nil
		}
	}

	return SourceFile{}, fmt.Errorf("source file not found: %s", path)
}

func (r *fileSystemSourceRepository) OpenSourceFile(file SourceFile) (io.ReadCloser, error) {
	return os.OpenFile(file.Path, os.O_RDONLY, 0)
}

func (r *fileSystemSourceRepository) enumSourceDir(path string, handler sourceFileHandlerFn) error {
	return filepath.WalkDir(path, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !r.isAcceptableSourceFile(path) {
			logger.Debugf("Ignoring file: %s", path)
			return nil
		}

		return handler(SourceFile{
			Path:       path,
			repository: r,
		})
	})
}

// A source file is acceptable if the base file name meets the following conditions:
//
// 1. It does not match any of the excluded globs
// 2. It matches any of the included globs
//
// If there are no included globs, then all files are acceptable.
func (r *fileSystemSourceRepository) isAcceptableSourceFile(path string) bool {
	baseFileName := filepath.Base(path)

	for _, excludedGlob := range r.config.ExcludedGlobs {
		matched, err := filepath.Match(excludedGlob, baseFileName)
		if err != nil {
			logger.Errorf("Invalid exclude glob pattern: %s: %v", excludedGlob, err)
			continue
		}

		if matched {
			return false
		}
	}

	if len(r.config.IncludedGlobs) == 0 {
		return true
	}

	for _, includedGlob := range r.config.IncludedGlobs {
		matched, err := filepath.Match(includedGlob, baseFileName)
		if err != nil {
			logger.Errorf("Invalid include glob pattern: %s: %v", includedGlob, err)
			continue
		}

		if matched {
			return true
		}
	}

	return false
}

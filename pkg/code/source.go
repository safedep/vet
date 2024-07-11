package code

import "io"

// Represents a source file. This is required because import resolution
// algorithm may need to know the path of the current file
type SourceFile struct {
	// Identifier for the source file. This is dependent on the
	// language on how to uniquely identify a source file
	Id string

	// Repository specific path to the file
	Path string

	// The repository from where the source file is retrieved
	repository SourceRepository
}

func (f SourceFile) Open() (io.ReadCloser, error) {
	return f.repository.OpenSourceFile(f)
}

func (f SourceFile) Repository() SourceRepository {
	return f.repository
}

// Check if the source file is imported. Returns true
// if the source file is relative to the source directories
// without considering any import directories
func (f SourceFile) IsImportedFile() bool {
	// When we don't have a repository, we assume that the file
	// is not valid. Let us consider it to be an unresolved import
	if f.repository == nil {
		return true
	}

	_, err := f.repository.GetRelativePath(f.Path, false)
	return (err != nil)
}

type sourceFileHandlerFn func(file SourceFile) error

// SourceRepository is a repository of source files. It can be a local
// repository such as a directory or a remote repository such as a git repository.
// The concept of repository is just to find 1P and 3P code while abstracting the
// underlying storage mechanism (e.g. local file system or remote git repository)
type SourceRepository interface {
	// Name of the repository
	Name() string

	// Enumerate all source files in the repository. This can be multiple
	// directories for a local source repository
	EnumerateSourceFiles(handler sourceFileHandlerFn) error

	// Get a source file by path. This function enumerates all directories
	// available in the repository to check for existence of the source file by path
	GetSourceFileByPath(path string, includeImports bool) (SourceFile, error)

	// Open a source file for reading
	OpenSourceFile(file SourceFile) (io.ReadCloser, error)

	// Configure the repository for a source language
	ConfigureForLanguage(language SourceLanguage)

	// Get relative path of the source file from the repository root
	// This is useful for constructing the import path. The first match is returned
	GetRelativePath(path string, includeImport bool) (string, error)
}

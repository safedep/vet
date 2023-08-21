package file_utils

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

func CreateEmptyTempFile() (string, error) {
	tempFile, err := os.CreateTemp(os.TempDir(), "temp-")
	if err != nil {
		return "", err
	}

	defer tempFile.Close()

	// Write empty content
	_, err = tempFile.Write([]byte(""))
	if err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

/**
 * CopyToTempFile copies the contents of the source `io.ReadCloser` to a temporary file on disk.
 *
 * @param src     The source `io.ReadCloser` containing the content to copy.
 * @param dir     The directory where the temporary file will be created. Can be an empty string to use the default system directory.
 * @param pattern The prefix of the temporary file's name.
 *
 * @return A pointer to the `os.File` representing the created temporary file.
 * @return Any error encountered during the copy operation.
 */
func CopyToTempFile(src io.ReadCloser, dir string, pattern string) (*os.File, error) {
	// Create a temporary file in the specified directory with the given pattern as the prefix.
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		log.Printf("Error while creating tmp dir %v", err) // If there was an error creating the temporary file, log it and return the error.
		return nil, err
	}

	// Copy the contents from the source `io.ReadCloser` to the temporary file.
	if _, err := f.ReadFrom(src); err != nil {
		log.Printf("Error while reading from src file stream %v", err) // If there was an error while copying, log it and return the error.
		return nil, err
	}

	// Close the temporary file to ensure all data is flushed to disk.
	if err := f.Close(); err != nil {
		log.Printf("Error while closing tmp file %v", err) // If there was an error closing the temporary file, log it.
	}

	return f, nil // Return the pointer to the temporary file and nil error if successful.
}

// CopyFile copies a file from the source path to the destination path.
// It returns an error if any error occurs during the file copying process.
func CopyFile(srcPath, destPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}

// CreateTempDirAndCopyFile creates a temporary directory, copies a file to it,
// and returns the path of the temporary directory.
// It returns the directory path and an error if any error occurs during the process.
func CreateTempDirAndCopyFile(filePath string, dstfilename string) (string, error) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "safedep")
	if err != nil {
		return "", err
	}

	if dstfilename == "" {
		dstfilename = filepath.Base(filePath)
	}

	destPath := filepath.Join(tempDir, dstfilename)

	err = CopyFile(filePath, destPath)
	if err != nil {
		os.RemoveAll(tempDir) // Clean up the temporary directory if copying fails
		return "", err
	}

	return tempDir, nil
}

func RemoveDirectory(path string) error {
	err := os.RemoveAll(path)
	if err != nil {
		return err
	}
	return nil
}

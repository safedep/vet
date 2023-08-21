package file_utils

import (
	"io"
	"log"
	"os"
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

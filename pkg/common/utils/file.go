package utils

import (
	"io"
	"os"
)

func CreateEmptyTempFile() (string, error) {
	tempFile, err := os.CreateTemp(os.TempDir(), "temp-")
	if err != nil {
		return "", err
	}

	defer tempFile.Close()

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
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}

	if _, err := f.ReadFrom(src); err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, err
	}

	return f, nil
}

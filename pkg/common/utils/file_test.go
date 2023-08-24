package utils

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateEmptyTempFile(t *testing.T) {
	filename, err := CreateEmptyTempFile()
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	if filename == "" {
		t.Fatal("Expected a filename, got empty string")
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatalf("Expected file to exist: %v", err)
	}

	err = os.Remove(filename)
	if err != nil {
		t.Fatalf("Failed to clean up: %v", err)
	}
}

func TestCopyToTempFile(t *testing.T) {
	srcContent := []byte("Hello, this is the source content")
	src := ioutil.NopCloser(bytes.NewReader(srcContent))
	dir := os.TempDir()
	pattern := "temp-file-test-"

	file, err := CopyToTempFile(src, dir, pattern)
	assert.NoError(t, err)
	defer file.Close()

	assert.FileExists(t, file.Name())

	fileContent, err := ioutil.ReadFile(file.Name())
	assert.NoError(t, err)
	assert.Equal(t, srcContent, fileContent)
}

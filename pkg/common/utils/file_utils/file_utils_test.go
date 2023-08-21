package file_utils

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCreateEmptyTempFile tests the CreateEmptyTempFile function
func TestCreateEmptyTempFile(t *testing.T) {
	filename, err := CreateEmptyTempFile()
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	if filename == "" {
		t.Fatal("Expected a filename, got empty string")
	}

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatalf("Expected file to exist: %v", err)
	}

	// Clean up
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

func TestCopyFile(t *testing.T) {
	srcContent := []byte("Hello, source file!")
	srcFile, err := ioutil.TempFile("", "test_src")
	if err != nil {
		t.Fatalf("Error creating source temp file: %v", err)
	}
	defer os.Remove(srcFile.Name())
	defer srcFile.Close()

	_, err = srcFile.Write(srcContent)
	if err != nil {
		t.Fatalf("Error writing to source temp file: %v", err)
	}

	destFile, err := ioutil.TempFile("", "test_dest")
	if err != nil {
		t.Fatalf("Error creating dest temp file: %v", err)
	}
	defer os.Remove(destFile.Name())
	defer destFile.Close()

	err = CopyFile(srcFile.Name(), destFile.Name())
	if err != nil {
		t.Fatalf("Error copying file: %v", err)
	}

	destContent, err := ioutil.ReadFile(destFile.Name())
	if err != nil {
		t.Fatalf("Error reading dest file: %v", err)
	}

	if string(destContent) != string(srcContent) {
		t.Error("Copied content doesn't match")
	}
}

func TestCreateTempDirAndCopyFile(t *testing.T) {
	srcContent := []byte("Hello, source file!")
	srcFile, err := ioutil.TempFile("", "test_src")
	if err != nil {
		t.Fatalf("Error creating source temp file: %v", err)
	}
	defer os.Remove(srcFile.Name())
	defer srcFile.Close()

	_, err = srcFile.Write(srcContent)
	if err != nil {
		t.Fatalf("Error writing to source temp file: %v", err)
	}

	tempDir, err := CreateTempDirAndCopyFile(srcFile.Name(), "dstfilename")
	if err != nil {
		t.Fatalf("Error creating temp dir and copying file: %v", err)
	}
	defer os.RemoveAll(tempDir)

	destFilePath := filepath.Join(tempDir, filepath.Base(srcFile.Name()))

	destContent, err := ioutil.ReadFile(destFilePath)
	if err != nil {
		t.Fatalf("Error reading copied file: %v", err)
	}

	if string(destContent) != string(srcContent) {
		t.Error("Copied content doesn't match")
	}
}

func TestRemoveDirectory(t *testing.T) {
	// Create a temporary directory with some files and subdirectories
	tempDir, err := ioutil.TempDir("", "testdir")
	if err != nil {
		t.Fatalf("Error creating temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := tempDir + "/testfile.txt"
	if err := ioutil.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	subDir := tempDir + "/subdir"
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Error creating subdirectory: %v", err)
	}

	// Remove the directory using the tested function
	err = RemoveDirectory(tempDir)
	if err != nil {
		t.Fatalf("Error removing directory: %v", err)
	}

	// Check if the directory and its contents are removed
	_, err = os.Stat(tempDir)
	if !os.IsNotExist(err) {
		t.Error("Directory was not removed")
	}

	_, err = os.Stat(filePath)
	if !os.IsNotExist(err) {
		t.Error("File was not removed")
	}

	_, err = os.Stat(subDir)
	if !os.IsNotExist(err) {
		t.Error("Subdirectory was not removed")
	}
}

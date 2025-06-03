package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var goDeps = []string{
	"connectrpc.com/connect",  // Direct
	"github.com/anchore/syft", // Direct
	"github.com/gocql/gocql",  // Direct
	"gopkg.in/inf.v0",         // indirect
}

func Test_GomodParser_Simple(t *testing.T) {
	manifest, err := parseGoModFile("./fixtures/go/go.mod", &ParserConfig{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 4, len(manifest.Packages))
	for _, pkg := range manifest.Packages {
		assert.Contains(t, goDeps, pkg.Name)
	}
}

func Test_GomodParser_Simple_NEW(t *testing.T) {
	// allFiles := strings.Split("./tmp/vet-github-113631725", "/")
	// modfile := allFiles[len(allFiles)-1]
	// fmt.Printf("modfile: %v\n", modfile)
	// newName := ""
	// if modfile != "go.mod" {
	// 	newName = strings.Join(allFiles[:len(allFiles)-1], "/")
	// }
	// finalName := newName

	originalPath := "/tmp/vet-github-113631725"
	newFileName := "renamed-file" // your desired new file name

	// Extract directory path
	dir := filepath.Dir(originalPath)
	fmt.Printf("dir: %v\n", dir)

	// Create new full path with the new file name
	newPath := filepath.Join(dir, newFileName)

	// Rename the file
	err := os.Rename(originalPath, newPath)
	if err != nil {
		fmt.Printf("Error renaming file: %v\n", err)
		return
	}

	fmt.Printf("File renamed from %s to %s\n", originalPath, newPath)

	// manifest, err := parseGoModFile("./fixtures/go/go.mod", &ParserConfig{})
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// assert.Equal(t, 5, len(manifest.Packages))
	// for _, pkg := range manifest.Packages {
	// 	assert.Contains(t, goDeps, pkg.Name)
	// }
}

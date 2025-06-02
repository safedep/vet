package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var goDeps = []string{
	"stdlib",                  // Direct
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

	assert.Equal(t, 5, len(manifest.Packages))
	for _, pkg := range manifest.Packages {
		assert.Contains(t, goDeps, pkg.Name)
	}
}

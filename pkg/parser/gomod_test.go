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

func TestGomodParser(t *testing.T) {
	tests := []struct {
		name                 string
		filePath             string
		config               *ParserConfig
		expectedPackageCount int
	}{
		{
			name:                 "Simple",
			filePath:             "./fixtures/go/go.mod",
			config:               &ParserConfig{},
			expectedPackageCount: 5,
		},
		{
			name:                 "Exclude Transitive Dependencies",
			filePath:             "./fixtures/go/go.mod",
			config:               &ParserConfig{ExcludeTransitiveDependencies: true},
			expectedPackageCount: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, err := parseGoModFile(tt.filePath, tt.config)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tt.expectedPackageCount, len(manifest.Packages))
			for _, pkg := range manifest.Packages {
				assert.Contains(t, goDeps, pkg.Name)
			}
		})
	}
}

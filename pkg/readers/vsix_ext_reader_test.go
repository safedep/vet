package readers

import (
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/models"
)

func TestVSCodeExtReaderInit(t *testing.T) {
	reader, err := NewVSIXExtReaderFromDefaultDistributions()
	assert.NoError(t, err)
	assert.NotNil(t, reader)
}

// TestVSCodeExtReaderForAllEditors tests each editor individually
func TestVSCodeExtReaderForAllEditors(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		expectedPkg     string
		expectedVersion string
		expectedEco     packagev1.Ecosystem
	}{
		{
			name:            "VSCode Editor",
			path:            ".vscode/extensions/",
			expectedPkg:     "ms-python.python",
			expectedVersion: "2023.20.0",
			expectedEco:     packagev1.Ecosystem_ECOSYSTEM_VSCODE,
		},
		{
			name:            "VSCodium Editor",
			path:            ".vscode-oss/extensions/",
			expectedPkg:     "redhat.java",
			expectedVersion: "1.20.0",
			expectedEco:     packagev1.Ecosystem_ECOSYSTEM_OPENVSX,
		},
		{
			name:            "Cursor Editor",
			path:            ".cursor/extensions/",
			expectedPkg:     "golang.go",
			expectedVersion: "0.39.1",
			expectedEco:     packagev1.Ecosystem_ECOSYSTEM_OPENVSX,
		},
		{
			name:            "Windsurf Editor",
			path:            ".windsurf/extensions/",
			expectedPkg:     "rust-lang.rust",
			expectedVersion: "0.7.9",
			expectedEco:     packagev1.Ecosystem_ECOSYSTEM_OPENVSX,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("./fixtures/vsix", tt.path)
			reader, err := NewVSIXExtReader([]string{path})
			assert.NoError(t, err)
			assert.NotNil(t, reader)

			err = reader.EnumManifests(func(manifest *models.PackageManifest, reader PackageReader) error {
				assert.NotNil(t, manifest)
				assert.NotNil(t, reader)

				packages := manifest.GetPackages()
				assert.Equal(t, 1, len(packages))
				assert.Equal(t, tt.expectedPkg, packages[0].GetName())
				assert.Equal(t, tt.expectedVersion, packages[0].GetVersion())
				assert.Equal(t, tt.expectedEco, packages[0].GetControlTowerSpecEcosystem())

				return nil
			})

			assert.NoError(t, err)
		})
	}
}

// TestVSCodeExtReaderWithMultipleEditors tests reading from multiple editors simultaneously
func TestVSCodeExtReaderWithMultipleEditors(t *testing.T) {
	paths := []string{
		"./fixtures/vsix/.vscode/extensions",
		"./fixtures/vsix/.vscode-oss/extensions",
		"./fixtures/vsix/.cursor/extensions",
		"./fixtures/vsix/.windsurf/extensions",
	}

	reader, err := NewVSIXExtReader(paths)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	foundPackages := make(map[string]bool)
	packageCount := 0

	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader PackageReader) error {
		assert.NotNil(t, manifest)
		packages := manifest.GetPackages()
		packageCount += len(packages)

		for _, pkg := range packages {
			foundPackages[pkg.GetName()] = true

			// Verify ecosystem based on package source
			switch pkg.GetName() {
			case "ms-python.python":
				assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_VSCODE, pkg.GetControlTowerSpecEcosystem())
			case "redhat.java", "golang.go", "rust-lang.rust":
				assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_OPENVSX, pkg.GetControlTowerSpecEcosystem())
			}
		}

		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 4, packageCount) // Should find all four extensions
	assert.True(t, foundPackages["ms-python.python"])
	assert.True(t, foundPackages["redhat.java"])
	assert.True(t, foundPackages["golang.go"])
	assert.True(t, foundPackages["rust-lang.rust"])
}

func TestVSCodeExtReaderWithInvalidPath(t *testing.T) {
	reader, err := NewVSIXExtReader([]string{"./fixtures/vsix/nonexistent"})
	assert.Error(t, err)
	assert.Nil(t, reader)
}

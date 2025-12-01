package readers

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

// Test data
var validBrewJSON = `[
  {
    "name": "git",
    "full_name": "git",
    "tap": "homebrew/core",
    "desc": "Distributed revision control system",
    "license": "GPL-2.0-only",
    "homepage": "https://git-scm.com",
    "versions": {
      "stable": "2.42.0"
    },
    "installed": [
      {
        "version": "2.42.0"
      }
    ]
  },
  {
    "name": "node",
    "full_name": "node",
    "tap": "homebrew/core",
    "desc": "Platform built on V8 to build network applications",
    "license": "MIT",
    "homepage": "https://nodejs.org/",
    "versions": {
      "stable": "20.8.0"
    },
    "installed": [
      {
        "version": "20.8.0"
      }
    ]
  }
]`

// mockBrewReader allows us to inject mock command execution
type mockBrewReader struct {
	config     BrewReaderConfig
	mockOutput []byte
	mockError  error
}

func (m *mockBrewReader) ApplicationName() (string, error) {
	return "homebrew", nil
}

func (m *mockBrewReader) Name() string {
	return "Homebrew Reader"
}

func (m *mockBrewReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	// Simulate command execution
	if m.mockError != nil {
		return fmt.Errorf("failed to execute brew command: %w", m.mockError)
	}

	var brewPackages []brewInfo
	if err := json.Unmarshal(m.mockOutput, &brewPackages); err != nil {
		return fmt.Errorf("failed to parse brew JSON output: %w", err)
	}

	manifest := models.NewPackageManifestFromHomebrew()

	for _, brewPkg := range brewPackages {
		version := ""
		for _, installed := range brewPkg.InstalledVersions {
			version = installed.Version
			break
		}

		pkg := &models.Package{
			PackageDetails: lockfile.PackageDetails{
				Name:      brewPkg.FullName,
				Version:   version,
				Ecosystem: lockfile.Ecosystem("brew"),
			},
			Insights: &insightapi.PackageVersionInsight{
				Licenses: &[]insightapi.License{
					insightapi.License(brewPkg.License),
				},
			},
		}
		manifest.AddPackage(pkg)
	}

	return handler(manifest, NewManifestModelReader(manifest))
}

func TestBrewReader_EnumManifests_Success(t *testing.T) {
	reader := &mockBrewReader{
		config:     BrewReaderConfig{},
		mockOutput: []byte(validBrewJSON),
		mockError:  nil,
	}

	var capturedManifest *models.PackageManifest
	var capturedPackages []*models.Package

	err := reader.EnumManifests(func(manifest *models.PackageManifest, pr PackageReader) error {
		capturedManifest = manifest

		return pr.EnumPackages(func(pkg *models.Package) error {
			capturedPackages = append(capturedPackages, pkg)
			return nil
		})
	})

	assert.NoError(t, err)
	assert.NotNil(t, capturedManifest)
	assert.Len(t, capturedPackages, 2)

	// Verify manifest source
	assert.Equal(t, models.ManifestSourceHomebrew, capturedManifest.Source.Type)
	assert.Equal(t, "brew.sh", capturedManifest.Source.Namespace)
	assert.Equal(t, "homebrew", capturedManifest.Source.Path)

	// Verify first package (git)
	gitPkg := capturedPackages[0]
	assert.Equal(t, "git", gitPkg.Name)
	assert.Equal(t, "2.42.0", gitPkg.Version)
	assert.Equal(t, lockfile.Ecosystem("brew"), gitPkg.Ecosystem)
	assert.NotNil(t, gitPkg.Insights)
	assert.NotNil(t, gitPkg.Insights.Licenses)
	assert.Equal(t, insightapi.License("GPL-2.0-only"), (*gitPkg.Insights.Licenses)[0])

	// Verify second package (node)
	nodePkg := capturedPackages[1]
	assert.Equal(t, "node", nodePkg.Name)
	assert.Equal(t, "20.8.0", nodePkg.Version)
	assert.Equal(t, lockfile.Ecosystem("brew"), nodePkg.Ecosystem)
	assert.NotNil(t, nodePkg.Insights)
	assert.NotNil(t, nodePkg.Insights.Licenses)
	assert.Equal(t, insightapi.License("MIT"), (*nodePkg.Insights.Licenses)[0])
}

func TestBrewReader_EnumManifests_EmptyResult(t *testing.T) {
	reader := &mockBrewReader{
		config:     BrewReaderConfig{},
		mockOutput: []byte("[]"),
		mockError:  nil,
	}

	var capturedPackages []*models.Package

	err := reader.EnumManifests(func(manifest *models.PackageManifest, pr PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			capturedPackages = append(capturedPackages, pkg)
			return nil
		})
	})

	assert.NoError(t, err)
	assert.Len(t, capturedPackages, 0)
}

func TestBrewReader_EnumManifests_SinglePackage(t *testing.T) {
	singlePackageJSON := `[
		{
			"name": "curl",
			"full_name": "curl",
			"tap": "homebrew/core",
			"desc": "Get a file from an HTTP, HTTPS or FTP server",
			"license": "curl",
			"homepage": "https://curl.se",
			"versions": {
				"stable": "8.4.0"
			},
			"installed": [
				{
					"version": "8.4.0"
				}
			]
		}
	]`

	reader := &mockBrewReader{
		config:     BrewReaderConfig{},
		mockOutput: []byte(singlePackageJSON),
		mockError:  nil,
	}

	var capturedPackages []*models.Package

	err := reader.EnumManifests(func(manifest *models.PackageManifest, pr PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			capturedPackages = append(capturedPackages, pkg)
			return nil
		})
	})

	assert.NoError(t, err)
	assert.Len(t, capturedPackages, 1)

	curlPkg := capturedPackages[0]
	assert.Equal(t, "curl", curlPkg.Name)
	assert.Equal(t, "8.4.0", curlPkg.Version)
	assert.Equal(t, lockfile.Ecosystem("brew"), curlPkg.Ecosystem)
	assert.Equal(t, insightapi.License("curl"), (*curlPkg.Insights.Licenses)[0])
}

func TestBrewReader_EnumManifests_MultipleVersions(t *testing.T) {
	multiVersionJSON := `[
		{
			"name": "openssl",
			"full_name": "openssl@3",
			"tap": "homebrew/core",
			"desc": "Cryptography and SSL/TLS Toolkit",
			"license": "Apache-2.0",
			"homepage": "https://openssl.org/",
			"versions": {
				"stable": "3.1.4"
			},
			"installed": [
				{
					"version": "3.1.3"
				},
				{
					"version": "3.1.4"
				}
			]
		}
	]`

	reader := &mockBrewReader{
		config:     BrewReaderConfig{},
		mockOutput: []byte(multiVersionJSON),
		mockError:  nil,
	}

	var capturedPackages []*models.Package

	err := reader.EnumManifests(func(manifest *models.PackageManifest, pr PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			capturedPackages = append(capturedPackages, pkg)
			return nil
		})
	})

	assert.NoError(t, err)
	assert.Len(t, capturedPackages, 1)

	// Should use first installed version
	opensslPkg := capturedPackages[0]
	assert.Equal(t, "openssl@3", opensslPkg.Name)
	assert.Equal(t, "3.1.3", opensslPkg.Version)
	assert.Equal(t, lockfile.Ecosystem("brew"), opensslPkg.Ecosystem)
}

func TestBrewReader_EnumManifests_NoInstalledVersions(t *testing.T) {
	noVersionsJSON := `[
		{
			"name": "test-package",
			"full_name": "test-package",
			"tap": "homebrew/core",
			"desc": "Test package",
			"license": "MIT",
			"homepage": "https://example.com",
			"versions": {
				"stable": "1.0.0"
			},
			"installed": []
		}
	]`

	reader := &mockBrewReader{
		config:     BrewReaderConfig{},
		mockOutput: []byte(noVersionsJSON),
		mockError:  nil,
	}

	var capturedPackages []*models.Package

	err := reader.EnumManifests(func(manifest *models.PackageManifest, pr PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			capturedPackages = append(capturedPackages, pkg)
			return nil
		})
	})

	assert.NoError(t, err)
	assert.Len(t, capturedPackages, 1)

	testPkg := capturedPackages[0]
	assert.Equal(t, "test-package", testPkg.Name)
	assert.Equal(t, "", testPkg.Version) // Empty when no installed versions
	assert.Equal(t, lockfile.Ecosystem("brew"), testPkg.Ecosystem)
}

func TestBrewInfo_JSONUnmarshal(t *testing.T) {
	var brewPackages []brewInfo
	err := json.Unmarshal([]byte(validBrewJSON), &brewPackages)

	require.NoError(t, err)
	assert.Len(t, brewPackages, 2)

	// Test first package structure
	git := brewPackages[0]
	assert.Equal(t, "git", git.Name)
	assert.Equal(t, "git", git.FullName)
	assert.Equal(t, "homebrew/core", git.Tap)
	assert.Equal(t, "Distributed revision control system", git.Desc)
	assert.Equal(t, "GPL-2.0-only", git.License)
	assert.Equal(t, "https://git-scm.com", git.Homepage)
	assert.Equal(t, "2.42.0", git.Versions.Stable)
	assert.Len(t, git.InstalledVersions, 1)
	assert.Equal(t, "2.42.0", git.InstalledVersions[0].Version)
}

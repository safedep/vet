package parser

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func findPackageInComposerManifest(manifest *models.PackageManifest, name, version string) *models.Package {
	for _, pkg := range manifest.GetPackages() {
		if pkg.GetName() == name && (version == "" || pkg.GetVersion() == version) {
			return pkg
		}
	}
	return nil
}

func TestComposerJSONParserBasic(t *testing.T) {
	pm, err := parseComposerJSON("./fixtures/composer.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	assert.NotNil(t, pm)
	assert.NotEmpty(t, pm.GetPackages())
}

func TestComposerJSONParserSpecificPackage(t *testing.T) {
	pm, err := parseComposerJSON("./fixtures/composer.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	monolog := findPackageInComposerManifest(pm, "monolog/monolog", "^2.0")
	assert.NotNil(t, monolog)
	assert.Equal(t, "^2.0", monolog.GetVersion())
}

func TestComposerJSONParserAllPackages(t *testing.T) {
	pm, err := parseComposerJSON("./fixtures/composer.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	expectedPackages := []string{
		"monolog/monolog",
		"guzzlehttp/guzzle",
		"symfony/console",
	}

	for _, packageName := range expectedPackages {
		pkg := findPackageInComposerManifest(pm, packageName, "")
		assert.NotNil(t, pkg, "Package %s should be present", packageName)
		assert.Equal(t, models.EcosystemPHPComposer, pm.Ecosystem)
	}
}

func TestComposerJSONParserPackageVersions(t *testing.T) {
	pm, err := parseComposerJSON("./fixtures/composer.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	packages := []struct {
		name    string
		version string
	}{
		{"monolog/monolog", "^2.0"},
		{"guzzlehttp/guzzle", "^7.0"},
		{"symfony/console", "^5.4"},
	}

	for _, pkg := range packages {
		foundPkg := findPackageInComposerManifest(pm, pkg.name, pkg.version)
		assert.NotNil(t, foundPkg, "Package %s@%s should be present", pkg.name, pkg.version)
		assert.Equal(t, pkg.version, foundPkg.GetVersion(), "Package %s should have version %s", pkg.name, pkg.version)
	}
}

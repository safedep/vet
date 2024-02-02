package parser

import (
	"os"
	"slices"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestParseCyclonedxSBOM(t *testing.T) {
	tempFile, _ := os.CreateTemp("", "sbom_*.json")

	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	sbomContent := `{
		"bomFormat": "CycloneDX",
		"metadata": {
			"component": {
				"name": "mybigapp",
				"version": "2.26.0",
				"type": "application",
				"purl": "pkg:pypi/mybigapp@2.26.0"
			}
		},
		"components": [
			{
				"group": "",
				"name": "requests",
				"version": "1.0",
				"purl": "pkg:pypi/requests@2.26.0"
			},
			{
				"group": "testgroup",
				"name": "lodash",
				"version": "2.0",
				"purl": "pkg:npm/testgroup/lodash@4.17.21"
			}
		]
	}`

	err := os.WriteFile(tempFile.Name(), []byte(sbomContent), 0644)
	assert.Nil(t, err)

	manifest, err := parseSbomCycloneDxAsGraph(tempFile.Name(), &ParserConfig{})
	assert.Nil(t, err)

	packages := manifest.GetPackages()

	assert.Equal(t, manifest.GetDisplayPath(), tempFile.Name())
	assert.Len(t, packages, 2)

	b := slices.ContainsFunc(packages, func(pkg *models.Package) bool {
		return pkg.GetName() == "requests" &&
			pkg.GetVersion() == "2.26.0"
	})

	assert.True(t, b)

	b = slices.ContainsFunc(packages, func(pkg *models.Package) bool {
		return pkg.GetName() == "testgroup/lodash" &&
			pkg.GetVersion() == "4.17.21"
	})

	assert.True(t, b)
}

func TestConvertSbomComponentToPackage(t *testing.T) {
	component := cdx.Component{
		Group:      "",
		Name:       "requests",
		Version:    "2.26.0",
		PackageURL: "pkg:pypi/requests@2.26.0",
	}

	ref, pd, err := cdxExtractPackageFromComponent(component)

	assert.Nil(t, err)
	assert.Equal(t, component.PackageURL, ref)
	assert.Equal(t, "requests", pd.Name)
	assert.Equal(t, "2.26.0", pd.Version)
	assert.Equal(t, lockfile.PipEcosystem, pd.Ecosystem)
}

func TestParseCyclonedxSBOMWithEmptyComponents(t *testing.T) {
	tempFile, _ := os.CreateTemp("", "sbom_*.json")

	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	sbomContent := `{}`
	err := os.WriteFile(tempFile.Name(), []byte(sbomContent), 0644)
	assert.Nil(t, err)

	_, err = parseSbomCycloneDxAsGraph(tempFile.Name(), &ParserConfig{})
	assert.NotNil(t, err)
}

func TestParseCyclonedxSBOMWithGradleSBOM(t *testing.T) {
	manifest, err := parseSbomCycloneDxAsGraph("./fixtures/bom-maven.json", &ParserConfig{})

	assert.Nil(t, err)
	assert.NotNil(t, manifest)
	assert.NotEmpty(t, manifest.GetPackages())

	dg := manifest.DependencyGraph
	assert.NotEmpty(t, dg.GetNodes())
	assert.NotEmpty(t, dg.GetPackages())

	pkg, err := purl.ParsePackageUrl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0?type=jar")
	assert.Nil(t, err)

	nodes := dg.GetDependencies(&models.Package{PackageDetails: pkg.GetPackageDetails()})
	assert.Equal(t, 2, len(nodes))

	assert.Equal(t, "com.fasterxml.jackson.core:jackson-annotations", nodes[0].GetName())
	assert.Equal(t, "com.fasterxml.jackson.core:jackson-core", nodes[1].GetName())
}

func TestParseCyclonedxSBOMWithMavenSBOM(t *testing.T) {
	manifest, err := parseSbomCycloneDxAsGraph("./fixtures/bom-dropwizard-cdx-example.json", &ParserConfig{})
	assert.Nil(t, err)
	assert.NotNil(t, manifest)

	packages := manifest.GetPackages()
	assert.Equal(t, 167, len(packages))

	pkg, err := purl.ParsePackageUrl("pkg:maven/io.dropwizard/dropwizard-client@1.3.15?type=jar")
	assert.Nil(t, err)

	nodes := manifest.DependencyGraph.GetDependencies(&models.Package{PackageDetails: pkg.GetPackageDetails()})
	assert.Equal(t, 5, len(nodes))

	nodes = manifest.DependencyGraph.PathToRoot(&models.Package{PackageDetails: pkg.GetPackageDetails()})
	assert.Equal(t, 1, len(nodes))
}

func TestParseCyclonedxSBOMWithNpmSBOM(t *testing.T) {
	manifest, err := parseSbomCycloneDxAsGraph("./fixtures/bom-juiceshop-cdx-example.json", &ParserConfig{})
	assert.Nil(t, err)
	assert.NotNil(t, manifest)

	assert.Equal(t, 840, len(manifest.GetPackages()))
}

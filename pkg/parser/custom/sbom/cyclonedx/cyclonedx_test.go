package cyclonedx

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

func TestParseCyclonedxSBOM(t *testing.T) {
	// Create a sample SBOM JSON file
	tempFile, _ := ioutil.TempFile("", "sbom_*.json")
	defer os.Remove(tempFile.Name())
	sbomContent := `{
		"Components": [
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
	err := ioutil.WriteFile(tempFile.Name(), []byte(sbomContent), 0644)
	assert.Nil(t, err)

	packages, err := Parse(tempFile.Name())

	assert.Nil(t, err)
	assert.Len(t, packages, 2)
	assert.Equal(t, "requests", packages[0].Name)
	assert.Equal(t, "testgroup/lodash", packages[1].Name)
}

func TestConvertSbomComponent2LPD(t *testing.T) {
	component := cdx.Component{
		Group:      "",
		Name:       "requests",
		Version:    "2.26.0",
		PackageURL: "pkg:pypi/requests@2.26.0",
	}

	pd, err := convertSbomComponent2LPD(&component)

	assert.Nil(t, err)
	assert.Equal(t, "requests", pd.Name)
	assert.Equal(t, "2.26.0", pd.Version)
	assert.Equal(t, lockfile.PipEcosystem, pd.Ecosystem)
}

func TestParseCyclonedxSBOM_WithEmptyComponents(t *testing.T) {
	// Create a sample SBOM JSON file
	tempFile, _ := ioutil.TempFile("", "sbom_*.json")
	defer os.Remove(tempFile.Name())
	sbomContent := `{
	}`
	err := ioutil.WriteFile(tempFile.Name(), []byte(sbomContent), 0644)
	assert.Nil(t, err)

	packages, err := Parse(tempFile.Name())

	assert.Nil(t, err)
	assert.Len(t, packages, 0)
}

func TestParseCyclonedxSBOM_WithMultipleFiles(t *testing.T) {
	fixtureDir := "fixtures/cydxsbom"
	filesToTest := []string{"bom-dpc-int1.json", "bom-du.json", "bom-npm1.json"}

	for _, filename := range filesToTest {
		t.Run(filename, func(t *testing.T) {
			// Construct the full file path
			filePath := filepath.Join(fixtureDir, filename)

			packages, err := Parse(filePath)

			assert.Nil(t, err)
			assert.NotNil(t, packages)
			assert.NotEmpty(t, packages)
			t.Logf("Packages from %s: %v", filename, packages)
			// You can add assertions for the parsed packages here
		})
	}
}

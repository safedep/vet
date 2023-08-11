package parser

import (
	"os"
	"io/ioutil"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseCyclonedxSBOM(t *testing.T) {
	// Create a sample SBOM JSON file
	tempFile, _ := ioutil.TempFile("", "sbom_*.json")
	defer os.Remove(tempFile.Name())
	sbomContent := `{
		"Components": [
			{
				"group": "testGroup",
				"name": "testName",
				"version": "1.0",
				"bom-ref": "pkg:pypi"
			},
			{
				"group": "testGroup2",
				"name": "testName2",
				"version": "2.0",
				"bom-ref": "pkg:npm"
			}
		]
	}`
	ioutil.WriteFile(tempFile.Name(), []byte(sbomContent), 0644)

	packages, err := parseCyclonedxSBOM(tempFile.Name())

	assert.Nil(t, err)
	assert.Len(t, packages, 2)
	assert.Equal(t, "testGroup:testName", packages[0].Name)
	assert.Equal(t, "testGroup2:testName2", packages[1].Name)
}

func TestConvertSbomComponent2LPD(t *testing.T) {
	component := Component{
		Group:   "testGroup",
		Name:    "testName",
		Version: "1.0",
		BomRef:  "pkg:pypi",
	}

	pd, err := convertSbomComponent2LPD(&component)

	assert.Nil(t, err)
	assert.Equal(t, "testGroup:testName", pd.Name)
	assert.Equal(t, "1.0", pd.Version)
	assert.Equal(t, lockfile.PipEcosystem, pd.Ecosystem)
}

func TestconvertBomRefAsEcosystem(t *testing.T) {
	ecosystem, err := convertBomRefAsEcosystem("pkg:pypi")

	assert.Nil(t, err)
	assert.Equal(t, lockfile.PipEcosystem, ecosystem)

	ecosystem, err = convertBomRefAsEcosystem("pkg:npm")

	assert.Nil(t, err)
	assert.Equal(t, lockfile.NpmEcosystem, ecosystem)

	ecosystem, err = convertBomRefAsEcosystem("pkg:unknown")

	assert.NotNil(t, err)
	assert.Equal(t, lockfile.NpmEcosystem, ecosystem) // As per your code, it defaults to lockfile.NpmEcosystem
}

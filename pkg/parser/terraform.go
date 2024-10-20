package parser

import (
	"fmt"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/safedep/vet/pkg/models"
	"os"

	"github.com/hashicorp/hcl/v2/hclparse"
)

type ProviderLock struct {
	Version     string   `hcl:"version"`
	Constraints string   `hcl:"constraints"`
	Hashes      []string `hcl:"hashes"`
}

type Lockfile struct {
	Providers map[string]ProviderLock `hcl:"provider,block"`
}

func ParseTerraformLockfile(path string) ([]lockfile.PackageDetails, error) {
	// Open the lockfile
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s", err)
	}
	defer file.Close()

	// Parse the file using the HCL parser
	parser := hclparse.NewParser()
	hclFile, diags := parser.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse lockfile: %v", diags)
	}

	// Define the structure for extracting providers
	// Traverse the body of the HCL file to find "provider" blocks
	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("failed to assert body as hclsyntax.Body")
	}
	var packageDetails []lockfile.PackageDetails
	for _, block := range body.Blocks {
		if block.Type == "provider" {
			providerName := block.Labels[0] // The provider name is the first label
			var providerVersion string
			// Decode the block's body into the ProviderLock struct
			if versionAttr, exists := block.Body.Attributes["version"]; exists {
				versionVal, diags := versionAttr.Expr.Value(nil)
				if diags.HasErrors() {
					return nil, fmt.Errorf("failed to extract version: %v", diags)
				}
				providerVersion = versionVal.AsString()
			}
			packageDetail := lockfile.PackageDetails{
				Name:      providerName,
				Version:   providerVersion,
				Ecosystem: models.EcoSystemTerraform,
				CompareAs: models.EcoSystemTerraform,
			}
			packageDetails = append(packageDetails, packageDetail)
		}
	}
	return packageDetails, nil
}

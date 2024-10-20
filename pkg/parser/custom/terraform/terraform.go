package terraform

import (
	"fmt"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/safedep/vet/pkg/models"
	"os"

	"github.com/hashicorp/hcl/v2/hclparse"
)

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

	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("failed to assert body as hclsyntax.Body")
	}
	var packageDetails []lockfile.PackageDetails
	for _, block := range body.Blocks {
		if block.Type == "provider" {
			providerName := block.Labels[0] // The provider name is the first label
			var providerVersion string
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

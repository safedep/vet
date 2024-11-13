package parser

import (
	"fmt"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

func parseTerraformLockfile(path string, config *ParserConfig) (*models.PackageManifest, error) {
	parser := hclparse.NewParser()
	hclFile, diags := parser.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse lockfile: %v", diags)
	}

	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("failed to assert body as hclsyntax.Body")
	}

	manifest := models.NewPackageManifestFromLocal(path, models.EcosystemTerraformProvider)
	for _, block := range body.Blocks {
		if block.Type != "provider" {
			continue
		}

		if len(block.Labels) == 0 {
			logger.Warnf("Terraform parser: provider block has no labels")
			continue
		}

		providerName := block.Labels[0] // The provider name is the first label
		providerVersion := "0.0.0"
		if versionAttr, exists := block.Body.Attributes["version"]; exists {
			versionVal, diags := versionAttr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("failed to extract version: %v", diags)
			}

			providerVersion = versionVal.AsString()
		}

		pkgdetails := models.NewPackageDetail(models.EcosystemTerraformProvider,
			providerName, providerVersion)
		packageModel := models.Package{
			PackageDetails: pkgdetails,
			Depth:          0,
		}

		manifest.AddPackage(&packageModel)
	}

	return manifest, nil
}

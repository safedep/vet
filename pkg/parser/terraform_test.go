package parser

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func findPackageInManifest(manifest *models.PackageManifest, name, version string) *models.Package {
	for _, pkg := range manifest.GetPackages() {
		if pkg.GetName() == name && (version == "" || pkg.GetVersion() == version) {
			return pkg
		}
	}
	return nil
}

func TestTerraformLockfileParserBasic(t *testing.T) {
	pm, err := parseTerraformLockfile("./fixtures/terraform.lock.hcl", defaultParserConfigForTest)
	assert.Nil(t, err)

	assert.NotNil(t, pm)
	assert.NotEmpty(t, pm.GetPackages())
}

func TestTerraformLockfileParserSpecificProvider(t *testing.T) {
	pm, err := parseTerraformLockfile("./fixtures/terraform.lock.hcl", defaultParserConfigForTest)
	assert.Nil(t, err)

	awsProvider := findPackageInManifest(pm, "registry.terraform.io/hashicorp/aws", "5.0.1")
	assert.NotNil(t, awsProvider)
	assert.Equal(t, "5.0.1", awsProvider.GetVersion())
}

func TestTerraformLockfileParserAllProviders(t *testing.T) {
	pm, err := parseTerraformLockfile("./fixtures/terraform.lock.hcl", defaultParserConfigForTest)
	assert.Nil(t, err)

	expectedProviders := []string{
		"registry.terraform.io/hashicorp/aws",
		"registry.terraform.io/hashicorp/google",
		"registry.terraform.io/datadog/datadog",
		"registry.terraform.io/hashicorp/kubernetes",
		"registry.terraform.io/integrations/github",
	}

	for _, providerName := range expectedProviders {
		provider := findPackageInManifest(pm, providerName, "")
		assert.NotNil(t, provider, "Provider %s should be present", providerName)
	}
}

func TestTerraformLockfileParserProviderVersions(t *testing.T) {
	pm, err := parseTerraformLockfile("./fixtures/terraform.lock.hcl", defaultParserConfigForTest)
	assert.Nil(t, err)

	providers := []struct {
		name    string
		version string
	}{
		{"registry.terraform.io/hashicorp/aws", "5.0.1"},
		{"registry.terraform.io/hashicorp/google", "4.59.0"},
		{"registry.terraform.io/datadog/datadog", "3.21.0"},
	}

	for _, provider := range providers {
		pkg := findPackageInManifest(pm, provider.name, provider.version)
		assert.NotNil(t, pkg, "Provider %s@%s should be present", provider.name, provider.version)
		assert.Equal(t, provider.version, pkg.GetVersion(), "Provider %s should have version %s", provider.name, provider.version)
	}
}

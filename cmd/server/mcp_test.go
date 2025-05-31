package server

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/vet/test"
	"github.com/stretchr/testify/assert"
)

func TestMcpDriver(t *testing.T) {
	test.EnsureEndToEndTestIsEnabled(t)

	driver, err := buildMcpDriver()
	if err != nil {
		t.Fatalf("failed to build MCP driver: %v", err)
	}

	t.Run("malysis community service is accessible", func(t *testing.T) {
		report, err := driver.GetPackageVersionMalwareReport(context.Background(), &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				Name:      "express",
			},
			Version: "4.17.1",
		})

		assert.NoError(t, err)
		assert.NotNil(t, report)
	})

	t.Run("insights community service is accessible", func(t *testing.T) {
		vulns, err := driver.GetPackageVersionVulnerabilities(context.Background(), &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				Name:      "express",
			},
			Version: "4.17.1",
		})

		assert.NoError(t, err)
		assert.NotNil(t, vulns)
		assert.NotEmpty(t, vulns)
	})

	t.Run("package registry adapter is accessible", func(t *testing.T) {
		res, err := driver.GetPackageLatestVersion(context.Background(), &packagev1.Package{
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			Name:      "express",
		})

		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, "express", res.GetPackage().GetName())
		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, res.GetPackage().GetEcosystem())
		assert.NotEmpty(t, res.GetPackage().GetName())
	})
}

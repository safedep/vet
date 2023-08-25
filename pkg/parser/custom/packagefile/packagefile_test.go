package packagefile

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

func TestConvert2LockfilePackageDetails(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Version:   "1.2.3",
		Ecosystem: lockfile.GoEcosystem,
		CompareAs: lockfile.GoEcosystem,
	}

	lockfilePd := pd.Convert2LockfilePackageDetails()

	assert.Equal(t, pd.Name, lockfilePd.Name)
	assert.Equal(t, pd.Version, lockfilePd.Version)
	assert.Equal(t, pd.Ecosystem, lockfilePd.Ecosystem)
	assert.Equal(t, pd.CompareAs, lockfilePd.CompareAs)
}

func TestCreateOssScannerPackageDetailName(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Group:     "test-group",
		Ecosystem: lockfile.GoEcosystem,
	}

	name := pd.createOssScannerPackageDetailName()

	expectedName := "test-group/test-package"
	assert.Equal(t, expectedName, name)
}

func TestGetNameWithoutGroup(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Ecosystem: lockfile.GoEcosystem,
	}

	name := pd.createOssScannerPackageDetailName()

	assert.Equal(t, pd.Name, name)
}

func TestGetNameWithDifferentEcosystem(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Group:     "test-group",
		Ecosystem: lockfile.NpmEcosystem,
	}

	name := pd.createOssScannerPackageDetailName()

	expectedName := "test-group/test-package"
	assert.Equal(t, expectedName, name)
}

func TestGetNameWithGroupAndDifferentEcosystem(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Group:     "test-group",
		Ecosystem: lockfile.NpmEcosystem,
	}

	name := pd.createOssScannerPackageDetailName()

	expectedName := "test-group/test-package"
	assert.Equal(t, expectedName, name)
}

func TestGetNameWithNoGroupAndDifferentEcosystem(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Ecosystem: lockfile.NpmEcosystem,
	}

	name := pd.createOssScannerPackageDetailName()

	assert.Equal(t, pd.Name, name)
}

func TestConvert2LockfilePackageDetailsWithDifferentEcosystem(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Version:   "1.2.3",
		Ecosystem: lockfile.NpmEcosystem,
		CompareAs: lockfile.NpmEcosystem,
	}

	lockfilePd := pd.Convert2LockfilePackageDetails()

	assert.Equal(t, pd.Name, lockfilePd.Name)
	assert.Equal(t, pd.Version, lockfilePd.Version)
	assert.Equal(t, pd.Ecosystem, lockfilePd.Ecosystem)
	assert.Equal(t, pd.CompareAs, lockfilePd.CompareAs)
}

func TestGetNameWithMavenEcosystem(t *testing.T) {
	pd := &PackageDetails{
		Name:      "test-package",
		Group:     "test-group",
		Ecosystem: lockfile.MavenEcosystem,
	}

	name := pd.createOssScannerPackageDetailName()

	expectedName := "test-group:test-package"
	assert.Equal(t, expectedName, name)
}

package sbom

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestParsePurlType(t *testing.T) {
	testCases := []struct {
		input       string
		expectedEco lockfile.Ecosystem
		expectedOk  bool
	}{
		{"github", models.EcosystemGitHubActions, true}, // Update with the expected ecosystem
		{"golang", lockfile.GoEcosystem, true},
		{"maven", lockfile.MavenEcosystem, true},
		{"npm", lockfile.NpmEcosystem, true},
		{"nuget", lockfile.NuGetEcosystem, true},
		{"composer", lockfile.ComposerEcosystem, true},
		{"pypi", lockfile.PipEcosystem, true},
		{"cargo", lockfile.CargoEcosystem, true},
		{"gem", lockfile.BundlerEcosystem, true}, // Update with the expected ecosystem for Ruby
		// Add more test cases here
	}

	for _, tc := range testCases {
		eco, err := PurlTypeToLockfileEcosystem(tc.input)
		assert.Equal(t, tc.expectedEco, eco, tc.input)
		if tc.expectedOk {
			assert.Nil(t, err, "did not expect an error")
		} else {
			assert.NotNil(t, err, "expected an error")
		}
	}
}

func TestCalculateCvssScore(t *testing.T) {
	testCases := []struct {
		vector        string
		expectedScore float64
	}{
		{"AV:N/AC:H/Au:S/C:C/I:P/A:C", 6.8},
		{"CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:L", 7.2},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7},
	}

	for _, tc := range testCases {
		score, err := CalculateCvssScore(tc.vector)
		assert.Nil(t, err)
		assert.Equal(t, tc.expectedScore, score, "unexpected CVSS score")
	}

	_, err := CalculateCvssScore("invalid vector")
	assert.Error(t, err, "expected an error for invalid vector")
}

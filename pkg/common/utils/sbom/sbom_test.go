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

// Add more test cases as needed for edge cases and different inputs

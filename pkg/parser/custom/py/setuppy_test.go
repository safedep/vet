package py_test

import (
	"testing"
	"github.com/safedep/vet/pkg/parser/custom/py"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseRequirementsFileLine(t *testing.T) {
	tests := []struct {
		input      string
		expected   lockfile.PackageDetails
		shouldFail bool // Set this to true for input that should fail parsing
	}{
		{
			input: "requests==2.26.0",
			expected: lockfile.PackageDetails{
				Name:      "requests",
				Version:   "2.26.0",
				Ecosystem: lockfile.PipEcosystem,
				CompareAs: lockfile.PipEcosystem,
			},
			shouldFail: false,
		},
		{
			input: "flask>=1.0",
			expected: lockfile.PackageDetails{
				Name:      "flask",
				Version:   "1.0",
				Ecosystem: lockfile.PipEcosystem,
				CompareAs: lockfile.PipEcosystem,
			},
			shouldFail: false,
		},
		{
			input: "numpy~=1.20",
			expected: lockfile.PackageDetails{
				Name:      "numpy",
				Version:   "1.20",
				Ecosystem: lockfile.PipEcosystem,
				CompareAs: lockfile.PipEcosystem,
			},
			shouldFail: false,
		},
		{
			input: "django!=2.0",
			expected: lockfile.PackageDetails{
				Name:      "django",
				Version:   "0.0.0",
				Ecosystem: lockfile.PipEcosystem,
				CompareAs: lockfile.PipEcosystem,
			},
			shouldFail: false,
		},
		{
			input: "bad-input", // Invalid input
			expected: lockfile.PackageDetails{
				Name:      "bad-input",
				Version:   "0.0.0",
				Ecosystem: lockfile.PipEcosystem,
				CompareAs: lockfile.PipEcosystem,
			},
			shouldFail: false,
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			if test.shouldFail {
				require.Panics(t, func() {
					parsed := py.ParseRequirementsFileLine(test.input)
					assert.Fail(t, "Shouldn't reach here", "Parsed: %#v", parsed)
				})
			} else {
				parsed := py.ParseRequirementsFileLine(test.input)
				assert.Equal(t, test.expected, parsed, "Parsed package details should match expected")
			}
		})
	}
}

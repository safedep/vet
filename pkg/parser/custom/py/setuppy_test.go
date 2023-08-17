package py

import (
	"fmt"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
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
					parsed := parseRequirementsFileLine(test.input)
					assert.Fail(t, "Shouldn't reach here", "Parsed: %#v", parsed)
				})
			} else {
				parsed := parseRequirementsFileLine(test.input)
				assert.Equal(t, test.expected, parsed, "Parsed package details should match expected")
			}
		})
	}
}

func TestParseSetuppy(t *testing.T) {
	tests := []struct {
		filepath     string
		expectedDeps []lockfile.PackageDetails
	}{
		{
			filepath: "./fixtures/setuppy/setup2_parser1.py", // Path to your test file
			expectedDeps: []lockfile.PackageDetails{
				{
					Name:      "google-cloud-storage",
					Version:   "0.0.0",
					Ecosystem: lockfile.PipEcosystem,
					CompareAs: lockfile.PipEcosystem,
				},
				{
					Name:      "google-cloud-pubsub",
					Version:   "2.0",
					Ecosystem: lockfile.PipEcosystem,
					CompareAs: lockfile.PipEcosystem,
				},
				{
					Name:      "knowledge-graph",
					Version:   "3.12.0",
					Ecosystem: lockfile.PipEcosystem,
					CompareAs: lockfile.PipEcosystem,
				},
				{
					Name:      "statistics",
					Version:   "0.0.0",
					Ecosystem: lockfile.PipEcosystem,
					CompareAs: lockfile.PipEcosystem,
				},
			},
		},
		// Add more test cases here
	}

	for _, test := range tests {
		t.Run(test.filepath, func(t *testing.T) {
			dependencies, err := ParseSetuppy(test.filepath)
			assert.Nil(t, err)

			if len(dependencies) != len(test.expectedDeps) {
				t.Fatalf("Expected %d dependencies, but got %d", len(test.expectedDeps), len(dependencies))
			}

			dep_map := make(map[string]lockfile.PackageDetails, 0)
			for _, v := range test.expectedDeps {
				dep_map[v.Name] = v
			}

			for _, v := range dependencies {
				ev, ok := dep_map[v.Name]
				assert.True(t, ok, fmt.Sprintf("Package %s not found in expected result", v.Name))
				assert.Equal(t, ev.Name, v.Name, fmt.Sprintf("Mismatch for the package: %s", v.Name))
				assert.Equal(t, ev.Version, v.Version, fmt.Sprintf("Mismatch for the package: %s", v.Name))
				assert.Equal(t, ev.Ecosystem, v.Ecosystem, fmt.Sprintf("Mismatch for the package: %s", v.Name))
				assert.Equal(t, ev.CompareAs, v.CompareAs, fmt.Sprintf("Mismatch for the package: %s", v.Name))
			}
		})
	}
}

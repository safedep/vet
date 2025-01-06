package filter

import (
	"testing"

	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestEvaluatorLicenseExpression(t *testing.T) {
	cases := []struct {
		name            string
		packageLicenses []string
		filterString    string
		expected        bool
		skip            bool
		skipReason      string
	}{
		{
			name:            "License match by exists (current behavior)",
			packageLicenses: []string{"MIT", "Apache-2.0"},
			filterString:    "licenses.exists(p, p == 'MIT')",
			expected:        true,
		},
		{
			name:            "Package has license expression does not match exists",
			packageLicenses: []string{"MIT OR Apache-2.0"},
			filterString:    "licenses.exists(p, p == 'MIT')",
			expected:        false,
		},
		{
			name:            "Package has license expression matches expression",
			packageLicenses: []string{"MIT OR Apache-2.0"},
			filterString:    "licenses.contains_license('MIT')",
			expected:        true,
		},
		{
			name:            "Package has license expression matches expression",
			packageLicenses: []string{"MIT OR Apache-2.0"},
			filterString:    "licenses.contains_license('Apache-2.0 OR MIT')",
			expected:        true,
		},
		{
			name:            "Package has license expression does not match expression",
			packageLicenses: []string{"MIT OR Apache-2.0"},
			filterString:    "licenses.contains_license('Apache-2.0 AND MIT')",
			expected:        false,
			skip:            true,
			skipReason:      "AND expressions in filters are not supported yet",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.skip {
				t.Skip(c.skipReason)
			}

			f, err := NewEvaluator("test", false)
			assert.NoError(t, err)

			err = f.AddFilter(&filtersuite.Filter{
				Name:  "test",
				Value: c.filterString,
			})
			assert.NoError(t, err)

			licenses := []insightapi.License{}
			for _, l := range c.packageLicenses {
				licenses = append(licenses, insightapi.License(l))
			}

			pkg := &models.Package{
				Insights: &insightapi.PackageVersionInsight{
					Licenses: &licenses,
				},
			}

			result, err := f.EvalPackage(pkg)
			assert.NoError(t, err)
			assert.Equal(t, c.expected, result.Matched())
		})
	}
}

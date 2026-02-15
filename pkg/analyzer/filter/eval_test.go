package filter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/common/clock"
	"github.com/safedep/vet/pkg/models"
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

			f, err := NewEvaluator("test", WithIgnoreError(false))
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

func TestEvaluator_NowFunction(t *testing.T) {
	pack := &models.Package{
		PackageDetails: models.NewPackageDetail(models.EcosystemGo, "test2", "1.0.0"),
		Manifest:       &models.PackageManifest{Ecosystem: models.EcosystemGo},
	}
	testClock := clock.NewFakePassiveClock(
		time.Date(2026, 2, 15, 13, 0, 0, 0, time.UTC),
	)

	t.Run("Function now() returns a timestamp", func(t *testing.T) {
		eval, _ := NewEvaluator("test", WithClock(testClock))
		filter := &filtersuite.Filter{
			Name:  "test now",
			Value: "now() == timestamp(\"2026-02-15T13:00:00Z\")",
		}
		err := eval.AddFilter(filter)
		assert.NoError(t, err)

		result, err := eval.EvalPackage(pack)
		assert.NoError(t, err)
		assert.Equal(t, true, result.Matched())
	})

	t.Run("Function now() can be converted to a duration", func(t *testing.T) {
		eval, _ := NewEvaluator("test", WithClock(testClock))
		filter := &filtersuite.Filter{
			Name:  "test now",
			Value: "(now() - timestamp(\"2026-02-15T10:00:00Z\")).getHours() == 3",
		}
		err := eval.AddFilter(filter)
		assert.NoError(t, err)

		result, err := eval.EvalPackage(pack)
		assert.NoError(t, err)
		assert.Equal(t, true, result.Matched())
	})

	t.Run("Now is a function", func(t *testing.T) {
		eval, _ := NewEvaluator("test", WithClock(testClock))
		filter := &filtersuite.Filter{
			Name:  "test now",
			Value: "now == timestamp(\"2026-02-15T10:00:00Z\")",
		}
		err := eval.AddFilter(filter)
		assert.Error(t, err, "ERROR: <input>:1:1: undeclared reference to 'now'")
	})
}

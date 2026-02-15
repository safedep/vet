package filterv2

import (
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/common/clock"
	"github.com/safedep/vet/pkg/models"
)

func TestEvaluator_AddRule(t *testing.T) {
	cases := []struct {
		name     string
		input    *models.Package
		policies []*policyv1.Policy
		match    bool
		errMsg   string
	}{
		{
			name: "Sanity Check",
			input: &models.Package{
				PackageDetails: models.NewPackageDetail(models.EcosystemGo, "test", "1.0.0"),
				Manifest: &models.PackageManifest{
					Ecosystem: models.EcosystemGo,
				},
				InsightsV2: &packagev1.PackageVersionInsight{},
			},
			policies: make([]*policyv1.Policy, 0),
			match:    false,
		},
		{
			name: "Package Name Match",
			input: &models.Package{
				PackageDetails: models.NewPackageDetail(models.EcosystemGo, "test", "1.0.0"),
				Manifest: &models.PackageManifest{
					Ecosystem: models.EcosystemGo,
				},
				InsightsV2: &packagev1.PackageVersionInsight{},
			},
			policies: []*policyv1.Policy{
				{
					Rules: []*policyv1.Rule{
						{
							Value: "_.package.name ==  \"test\"",
						},
					},
				},
			},
			match: true,
		},
		{
			name: "Package name does not match",
			input: &models.Package{
				PackageDetails: models.NewPackageDetail(models.EcosystemGo, "test2", "1.0.0"),
				Manifest: &models.PackageManifest{
					Ecosystem: models.EcosystemGo,
				},
				InsightsV2: &packagev1.PackageVersionInsight{},
			},
			policies: []*policyv1.Policy{
				{
					Rules: []*policyv1.Rule{
						{
							Value: "_.package.name ==  \"test\"",
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator, err := NewEvaluator("test", WithIgnoreError(true))
			assert.NoError(t, err)
			assert.NotNil(t, evaluator)

			for _, policy := range tc.policies {
				err := evaluator.AddPolicy(policy)
				assert.NoError(t, err)
			}

			result, err := evaluator.EvaluatePackage(tc.input)
			if tc.errMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.match, result.Matched())
			}
		})
	}
}

func TestEvaluator_NowFunction(t *testing.T) {
	pack := &models.Package{
		PackageDetails: models.NewPackageDetail(models.EcosystemGo, "test2", "1.0.0"),
		Manifest:       &models.PackageManifest{Ecosystem: models.EcosystemGo},
		InsightsV2:     &packagev1.PackageVersionInsight{},
	}
	testClock := clock.NewFakePassiveClock(
		time.Date(2026, 2, 15, 13, 0, 0, 0, time.UTC),
	)

	t.Run("Function now() returns a timestamp", func(t *testing.T) {
		eval, _ := NewEvaluator("test", WithClock(testClock))
		policy := &policyv1.Policy{
			Rules: []*policyv1.Rule{
				{
					Value: "now() == timestamp(\"2026-02-15T13:00:00Z\")",
				},
			},
		}
		err := eval.AddPolicy(policy)
		assert.NoError(t, err)

		result, err := eval.EvaluatePackage(pack)
		assert.NoError(t, err)
		assert.Equal(t, true, result.Matched())
	})

	t.Run("Function now() can be converted to a duration", func(t *testing.T) {
		eval, _ := NewEvaluator("test", WithClock(testClock))
		policy := &policyv1.Policy{
			Rules: []*policyv1.Rule{
				{
					Value: "(now() - timestamp(\"2026-02-15T10:00:00Z\")).getHours() == 3",
				},
			},
		}
		err := eval.AddPolicy(policy)
		assert.NoError(t, err)

		result, err := eval.EvaluatePackage(pack)
		assert.NoError(t, err)
		assert.Equal(t, true, result.Matched())
	})

	t.Run("Now is a function", func(t *testing.T) {
		eval, _ := NewEvaluator("test", WithClock(testClock))
		policy := &policyv1.Policy{
			Rules: []*policyv1.Rule{
				{
					Value: "now == timestamp(\"2026-02-15T10:00:00Z\")",
				},
			},
		}
		err := eval.AddPolicy(policy)
		assert.Error(t, err, "ERROR: <input>:1:1: undeclared reference to 'now'")
	})
}

func TestEvaluator_Options(t *testing.T) {
	t.Run("Default ignoreError is false", func(t *testing.T) {
		evaluator, err := NewEvaluator("test")
		assert.NoError(t, err)
		assert.NotNil(t, evaluator)
		assert.False(t, evaluator.ignoreError)
	})

	t.Run("WithIgnoreError sets ignoreError to true", func(t *testing.T) {
		evaluator, err := NewEvaluator("test", WithIgnoreError(true))
		assert.NoError(t, err)
		assert.NotNil(t, evaluator)
		assert.True(t, evaluator.ignoreError)
	})

	t.Run("WithIgnoreError sets ignoreError to false", func(t *testing.T) {
		evaluator, err := NewEvaluator("test", WithIgnoreError(false))
		assert.NoError(t, err)
		assert.NotNil(t, evaluator)
		assert.False(t, evaluator.ignoreError)
	})

	t.Run("Multiple options can be applied", func(t *testing.T) {
		evaluator, err := NewEvaluator("test", WithIgnoreError(true))
		assert.NoError(t, err)
		assert.NotNil(t, evaluator)
		assert.True(t, evaluator.ignoreError)
		assert.Equal(t, "test", evaluator.name)
	})
}

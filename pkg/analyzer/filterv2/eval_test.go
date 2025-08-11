package filterv2

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
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
			evaluator, err := NewEvaluator("test", true)
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

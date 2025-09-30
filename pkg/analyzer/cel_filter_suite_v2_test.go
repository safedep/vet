package analyzer

import (
	"testing"

	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/stretchr/testify/assert"
)

func TestPolicyV2LoadPolicyFromFile(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		policyName string
		rulesCount int
		errMsg     string
	}{
		{
			"valid policy v2",
			"fixtures/policy_v2_valid.yml",
			"Valid Policy V2",
			2,
			"",
		},
		{
			"invalid policy v2",
			"fixtures/policy_v2_invalid.yml",
			"",
			0,
			"unknown field",
		},
		{
			"policy file does not exist",
			"fixtures/policy_v2_does_not_exist.yml",
			"",
			0,
			"no such file or directory",
		},
		{
			"invalid check type",
			"fixtures/policy_v2_invalid_check_type.yml",
			"",
			0,
			"invalid value for enum field check",
		},
		{
			"missing check type",
			"fixtures/policy_v2_check_type_missing.yml",
			"Check Type Missing Policy",
			1,
			"",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			policy, err := policyV2LoadPolicyFromFile(test.path)
			if test.errMsg != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, test.errMsg)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.policyName, policy.GetName())
				assert.Equal(t, test.rulesCount, len(policy.GetRules()))
			}
		})
	}
}

func TestPolicyV2RuleParams(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		ruleIdx  int
		assertFn func(t *testing.T, rule *policyv1.Rule)
	}{
		{
			"Rule has labels",
			"fixtures/policy_v2_valid.yml",
			0,
			func(t *testing.T, rule *policyv1.Rule) {
				// Policy has labels, check at policy level
				policy, err := policyV2LoadPolicyFromFile("fixtures/policy_v2_valid.yml")
				assert.Nil(t, err)
				assert.Equal(t, 2, len(policy.GetLabels()))
				assert.Equal(t, "test", policy.Labels[0])
				assert.Equal(t, "valid", policy.Labels[1])
			},
		},
		{
			"Rule has valid check type",
			"fixtures/policy_v2_valid.yml",
			1,
			func(t *testing.T, rule *policyv1.Rule) {
				assert.Equal(t, policyv1.RuleCheck_RULE_CHECK_VULNERABILITY, rule.Check)
				assert.Equal(t, "Test rule 2 with vulnerability check", rule.Description)
			},
		},
		{
			"Rule with missing check type defaults to unknown",
			"fixtures/policy_v2_check_type_missing.yml",
			0,
			func(t *testing.T, rule *policyv1.Rule) {
				assert.Equal(t, policyv1.RuleCheck_RULE_CHECK_UNSPECIFIED, rule.Check)
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			policy, err := policyV2LoadPolicyFromFile(test.file)
			assert.Nil(t, err)

			rule := policy.Rules[test.ruleIdx]
			assert.NotNil(t, rule)

			test.assertFn(t, rule)
		})
	}
}

func TestNewCelFilterSuiteV2Analyzer(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		failOnMatch bool
		expectError bool
		errMsg      string
	}{
		{
			"create analyzer with valid policy",
			"fixtures/policy_v2_valid.yml",
			false,
			false,
			"",
		},
		{
			"create analyzer with fail on match enabled",
			"fixtures/policy_v2_valid.yml",
			true,
			false,
			"",
		},
		{
			"create analyzer with invalid policy file",
			"fixtures/policy_v2_invalid.yml",
			false,
			true,
			"unknown field",
		},
		{
			"create analyzer with non-existent file",
			"fixtures/policy_v2_does_not_exist.yml",
			false,
			true,
			"no such file or directory",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			analyzer, err := NewCelFilterSuiteV2Analyzer(test.path, test.failOnMatch)
			if test.expectError {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, test.errMsg)
				assert.Nil(t, analyzer)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, analyzer)
				assert.Equal(t, "CEL Filter Suite V2 Analyzer", analyzer.Name())

				// Verify internal state
				v2Analyzer, ok := analyzer.(*celFilterSuiteV2Analyzer)
				assert.True(t, ok)
				assert.Equal(t, test.failOnMatch, v2Analyzer.failOnMatch)
				assert.NotNil(t, v2Analyzer.evaluator)
				assert.NotNil(t, v2Analyzer.packages)
			}
		})
	}
}
package analyzer

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFilterSuiteV2AnalyzerAnalyze(t *testing.T) {
	testCases := []struct {
		name            string
		policyFile      string
		failOnMatch     bool
		manifest        *models.PackageManifest
		setupPackages   func() []*models.Package
		expectedMatches int
		expectedEvents  []AnalyzerEventType
		expectError     bool
		validateEvents  func(t *testing.T, events []*AnalyzerEvent)
	}{
		{
			name:        "No packages in manifest",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
				Packages:  []*models.Package{},
			},
			setupPackages:   func() []*models.Package { return []*models.Package{} },
			expectedMatches: 0,
			expectedEvents:  []AnalyzerEventType{},
			expectError:     false,
		},
		{
			name:        "Package without InsightsV2 data",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "test-pkg", "1.0.0"),
						InsightsV2:     nil, // No InsightsV2 data
					},
				}
			},
			expectedMatches: 0,
			expectedEvents:  []AnalyzerEventType{},
			expectError:     false,
		},
		{
			name:        "Single package matches policy rule with always true",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				pkg := &models.Package{
					PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "lodash", "4.17.21"),
					InsightsV2:     &packagev1.PackageVersionInsight{},
				}
				return []*models.Package{pkg}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, ET_FilterExpressionMatched, events[0].Type)
				assert.Equal(t, "lodash", events[0].Package.GetName())
				assert.NotNil(t, events[0].Filter)
				assert.NotNil(t, events[0].FilterV2Policy)
				assert.NotNil(t, events[0].FilterV2Rule)
				assert.Equal(t, "Valid Policy V2", events[0].FilterV2Policy.GetName())
				assert.Equal(t, "test-rule-1", events[0].FilterV2Rule.GetName())
			},
		},
		{
			name:        "Package matches vulnerability filter - high severity",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "vulnerable-pkg", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{
										Value: "GHSA-xxxx-yyyy-zzzz",
									},
									Severities: []*vulnerabilityv1.Severity{
										{
											Risk:  vulnerabilityv1.Severity_RISK_HIGH,
											Score: "7.5",
										},
									},
								},
							},
						},
					},
				}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, "vulnerable-pkg", events[0].Package.GetName())
				assert.NotNil(t, events[0].FilterV2Policy)
				assert.NotNil(t, events[0].FilterV2Rule)
			},
		},
		{
			name:        "Multiple packages, both match first rule",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "safe-pkg", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "critical-vuln-pkg", "2.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{
										Value: "CVE-2024-1234",
									},
									Severities: []*vulnerabilityv1.Severity{
										{
											Risk:  vulnerabilityv1.Severity_RISK_CRITICAL,
											Score: "9.8",
										},
									},
								},
							},
						},
					},
				}
			},
			expectedMatches: 2,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched, ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 2)
				// Both packages match the "true" rule
				assert.Equal(t, "safe-pkg", events[0].Package.GetName())
				assert.NotNil(t, events[0].FilterV2Policy)
				assert.NotNil(t, events[0].FilterV2Rule)
				assert.Equal(t, "critical-vuln-pkg", events[1].Package.GetName())
				assert.NotNil(t, events[1].FilterV2Policy)
				assert.NotNil(t, events[1].FilterV2Rule)
			},
		},
		{
			name:        "Match with failOnMatch flag - should trigger fail event",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: true,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "vulnerable-pkg", "1.0.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
				}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched, ET_AnalyzerFailOnError},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 2)
				assert.Equal(t, ET_FilterExpressionMatched, events[0].Type)
				assert.NotNil(t, events[0].FilterV2Policy)
				assert.NotNil(t, events[0].FilterV2Rule)
				assert.Equal(t, ET_AnalyzerFailOnError, events[1].Type)
				assert.Equal(t, "policy-suite-filter-fail-fast", events[1].Message)
			},
		},
		{
			name:        "No match with failOnMatch flag - should not trigger fail event",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: true,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "safe-pkg", "1.0.0"),
						InsightsV2:     nil, // No insights means no match
					},
				}
			},
			expectedMatches: 0,
			expectedEvents:  []AnalyzerEventType{},
			expectError:     false,
		},
		{
			name:        "Duplicate packages should only match once",
			policyFile:  "fixtures/policy_v2_valid.yml",
			failOnMatch: false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				pkg1 := &models.Package{
					PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "duplicated", "1.0.0"),
					InsightsV2:     &packagev1.PackageVersionInsight{},
				}
				pkg2 := &models.Package{
					PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "duplicated", "1.0.0"),
					InsightsV2:     &packagev1.PackageVersionInsight{},
				}
				return []*models.Package{pkg1, pkg2}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, "duplicated", events[0].Package.GetName())
				assert.NotNil(t, events[0].FilterV2Policy)
				assert.NotNil(t, events[0].FilterV2Rule)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create analyzer
			analyzer, err := NewCelFilterSuiteV2Analyzer(tc.policyFile, tc.failOnMatch)
			require.NoError(t, err, "Failed to create analyzer")
			require.NotNil(t, analyzer)

			// Setup packages
			packages := tc.setupPackages()
			tc.manifest.Packages = packages

			// Link packages to manifest
			for _, pkg := range packages {
				pkg.Manifest = tc.manifest
			}

			// Collect events
			capturedEvents := []*AnalyzerEvent{}
			handler := func(event *AnalyzerEvent) error {
				capturedEvents = append(capturedEvents, event)
				return nil
			}

			// Execute Analyze
			err = analyzer.Analyze(tc.manifest, handler)

			// Validate error expectation
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Validate event count
			assert.Len(t, capturedEvents, len(tc.expectedEvents), "Event count mismatch")

			// Validate event types
			for i, expectedType := range tc.expectedEvents {
				assert.Equal(t, expectedType, capturedEvents[i].Type, "Event type mismatch at index %d", i)
			}

			// Access internal state to verify matches
			v2Analyzer := analyzer.(*celFilterSuiteV2Analyzer)
			assert.Equal(t, tc.expectedMatches, len(v2Analyzer.packages), "Matched package count mismatch")
			assert.Equal(t, tc.expectedMatches, v2Analyzer.stat.MatchedPackages(), "Stat matched package count mismatch")

			// Validate packages count
			assert.Equal(t, len(packages), v2Analyzer.stat.EvaluatedPackages(), "Evaluated package count mismatch")

			// Validate manifests count
			if len(packages) > 0 {
				assert.Equal(t, 1, v2Analyzer.stat.evaluatedManifests, "Evaluated manifest count should be 1")
			}

			// Run custom validation if provided
			if tc.validateEvents != nil {
				if len(capturedEvents) > 0 {
					tc.validateEvents(t, capturedEvents)
				} else if len(tc.expectedEvents) > 0 {
					// If we expected events but got none, we should still run validation
					// to allow it to fail appropriately
					tc.validateEvents(t, capturedEvents)
				}
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
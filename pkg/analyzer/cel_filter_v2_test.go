package analyzer

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterV2AnalyzerAnalyze(t *testing.T) {
	testCases := []struct {
		name             string
		filterExpression string
		failOnMatch      bool
		manifest         *models.PackageManifest
		setupPackages    func() []*models.Package
		expectedMatches  int
		expectedEvents   []AnalyzerEventType
		expectError      bool
		validateEvents   func(t *testing.T, events []*AnalyzerEvent)
	}{
		{
			name:             "No packages in manifest",
			filterExpression: "_.package.name == \"test\"",
			failOnMatch:      false,
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
			name:             "Package without InsightsV2 data",
			filterExpression: "_.package.name == \"test-pkg\"",
			failOnMatch:      false,
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
			name:             "Single package matches by name",
			filterExpression: "_.package.name == \"lodash\"",
			failOnMatch:      false,
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
				assert.NotNil(t, events[0].FilterV2)
			},
		},
		{
			name:             "Package does not match filter",
			filterExpression: "_.package.name == \"express\"",
			failOnMatch:      false,
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
			expectedMatches: 0,
			expectedEvents:  []AnalyzerEventType{},
			expectError:     false,
		},
		{
			name:             "Multiple packages, only one matches",
			filterExpression: "_.package.name == \"react\"",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "lodash", "4.17.21"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "react", "18.2.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "vue", "3.3.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
				}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, "react", events[0].Package.GetName())
			},
		},
		{
			name:             "Multiple packages match the filter",
			filterExpression: "_.package.name.startsWith(\"lodash\") || _.package.name.startsWith(\"react\")",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "lodash", "4.17.21"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "react", "18.2.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
				}
			},
			expectedMatches: 2,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched, ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 2)
				assert.Equal(t, ET_FilterExpressionMatched, events[0].Type)
				assert.Equal(t, ET_FilterExpressionMatched, events[1].Type)
			},
		},
		{
			name:             "Match with failOnMatch flag - should trigger fail event",
			filterExpression: "_.package.name == \"vulnerable-pkg\"",
			failOnMatch:      true,
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
				assert.Equal(t, ET_AnalyzerFailOnError, events[1].Type)
				assert.Equal(t, "policy-filter-fail-fast", events[1].Message)
			},
		},
		{
			name:             "No match with failOnMatch flag - should not trigger fail event",
			filterExpression: "_.package.name == \"non-existent\"",
			failOnMatch:      true,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "safe-pkg", "1.0.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
				}
			},
			expectedMatches: 0,
			expectedEvents:  []AnalyzerEventType{},
			expectError:     false,
		},
		{
			name:             "Filter by version",
			filterExpression: "_.package.version == \"1.2.3\"",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/go.mod",
				Ecosystem: models.EcosystemGo,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemGo, "github.com/pkg/errors", "1.2.3"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemGo, "github.com/pkg/errors", "2.0.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
				}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
		},
		{
			name:             "Filter by vulnerability presence",
			filterExpression: "_.package.vulnerabilities.size() > 0",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/requirements.txt",
				Ecosystem: models.EcosystemPyPI,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemPyPI, "safe-package", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemPyPI, "vulnerable-package", "1.0.0"),
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
				assert.Equal(t, "vulnerable-package", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by license",
			filterExpression: "_.package.licenses.size() > 0",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "unlicensed", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Licenses: &packagev1.LicenseMetaList{
								Licenses: []*packagev1.LicenseMeta{},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "mit-licensed", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Licenses: &packagev1.LicenseMetaList{
								Licenses: []*packagev1.LicenseMeta{
									{
										LicenseId: "MIT",
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
				assert.Equal(t, "mit-licensed", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by direct dependency attribute",
			filterExpression: "_.package.attributes.direct == true",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/pom.xml",
				Ecosystem: models.EcosystemMaven,
			},
			setupPackages: func() []*models.Package {
				directPkg := &models.Package{
					PackageDetails: models.NewPackageDetail(models.EcosystemMaven, "com.example:direct", "1.0.0"),
					InsightsV2:     &packagev1.PackageVersionInsight{},
				}
				directPkg.Depth = 0 // Direct dependency

				transitivePkg := &models.Package{
					PackageDetails: models.NewPackageDetail(models.EcosystemMaven, "com.example:transitive", "1.0.0"),
					InsightsV2:     &packagev1.PackageVersionInsight{},
				}
				transitivePkg.Depth = 1 // Transitive dependency

				return []*models.Package{directPkg, transitivePkg}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, "com.example:direct", events[0].Package.GetName())
			},
		},
		{
			name:             "Complex filter with AND condition",
			filterExpression: "_.package.name.contains(\"npm\") && _.package.vulnerabilities.size() > 0",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "npm-safe", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemGo, "go-vulnerable", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{Value: "GHSA-1234"},
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "npm-vulnerable", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{Value: "GHSA-5678"},
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
				assert.Equal(t, "npm-vulnerable", events[0].Package.GetName())
			},
		},
		{
			name:             "Duplicate packages should only match once",
			filterExpression: "_.package.name == \"duplicated\"",
			failOnMatch:      false,
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
			},
		},
		{
			name:             "Filter with string contains",
			filterExpression: "_.package.name.contains(\"test\")",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "my-test-lib", "1.0.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "production-lib", "1.0.0"),
						InsightsV2:     &packagev1.PackageVersionInsight{},
					},
				}
			},
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, "my-test-lib", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by CVE severity",
			filterExpression: "_.package.vulnerabilities.exists(v, v.severity == \"CRITICAL\")",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/Cargo.toml",
				Ecosystem: models.EcosystemCargo,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemCargo, "low-risk", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{Value: "RUSTSEC-1"},
									Severities: []*vulnerabilityv1.Severity{
										{
											Risk:  vulnerabilityv1.Severity_RISK_LOW,
											Score: "3.0",
										},
									},
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemCargo, "critical-risk", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{Value: "RUSTSEC-2"},
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
			expectedMatches: 1,
			expectedEvents:  []AnalyzerEventType{ET_FilterExpressionMatched},
			expectError:     false,
			validateEvents: func(t *testing.T, events []*AnalyzerEvent) {
				require.Len(t, events, 1)
				assert.Equal(t, "critical-risk", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by CVSS score threshold",
			filterExpression: "_.package.vulnerabilities.exists(v, v.cvss_score >= 7.0)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "low-score", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{Value: "CVE-1"},
									Severities: []*vulnerabilityv1.Severity{
										{
											Risk:  vulnerabilityv1.Severity_RISK_MEDIUM,
											Score: "5.5",
										},
									},
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "high-score", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{Value: "CVE-2"},
									Severities: []*vulnerabilityv1.Severity{
										{
											Risk:  vulnerabilityv1.Severity_RISK_HIGH,
											Score: "8.2",
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
				if len(events) == 0 {
					t.Fatal("Expected at least 1 event but got 0")
				}
				assert.Equal(t, "high-score", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter with project insights",
			filterExpression: "_.package.projects.size() > 0",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "no-project", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "with-project", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Url:  "https://github.com/test/repo",
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
				assert.Equal(t, "with-project", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by GitHub stars - high popularity",
			filterExpression: "_.package.projects.exists(p, p.stars >= 10000)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				lowStars := int64(1000)
				highStars := int64(50000)
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "low-popularity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "low-popularity/repo",
										Url:  "https://github.com/low-popularity/repo",
									},
									Stars: &lowStars,
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "high-popularity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "high-popularity/repo",
										Url:  "https://github.com/high-popularity/repo",
									},
									Stars: &highStars,
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
				assert.Equal(t, "high-popularity", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by GitHub stars - low popularity threshold",
			filterExpression: "_.package.projects.exists(p, p.stars < 1000)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				veryLowStars := int64(50)
				mediumStars := int64(5000)
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "very-low-popularity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "very-low-popularity/repo",
										Url:  "https://github.com/very-low-popularity/repo",
									},
									Stars: &veryLowStars,
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "medium-popularity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "medium-popularity/repo",
										Url:  "https://github.com/medium-popularity/repo",
									},
									Stars: &mediumStars,
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
				assert.Equal(t, "very-low-popularity", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by GitHub forks - high activity",
			filterExpression: "_.package.projects.exists(p, p.forks >= 1000)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				lowForks := int64(10)
				highForks := int64(5000)
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "low-activity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "low-activity/repo",
										Url:  "https://github.com/low-activity/repo",
									},
									Forks: &lowForks,
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "high-activity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "high-activity/repo",
										Url:  "https://github.com/high-activity/repo",
									},
									Forks: &highForks,
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
				assert.Equal(t, "high-activity", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by GitHub contributors - active community",
			filterExpression: "_.package.projects.exists(p, p.contributors >= 50)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				lowContributors := int64(5)
				highContributors := int64(200)
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "small-community", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "small-community/repo",
										Url:  "https://github.com/small-community/repo",
									},
									Contributors: &lowContributors,
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "large-community", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "large-community/repo",
										Url:  "https://github.com/large-community/repo",
									},
									Contributors: &highContributors,
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
				assert.Equal(t, "large-community", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by complex popularity metrics - stars and forks",
			filterExpression: "_.package.projects.exists(p, p.stars >= 5000 && p.forks >= 500)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				lowStars := int64(1000)
				lowForks := int64(50)
				highStars := int64(10000)
				highForks := int64(2000)
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "moderate-popularity", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "moderate-popularity/repo",
										Url:  "https://github.com/moderate-popularity/repo",
									},
									Stars: &lowStars,
									Forks: &lowForks,
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "very-popular", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "very-popular/repo",
										Url:  "https://github.com/very-popular/repo",
									},
									Stars: &highStars,
									Forks: &highForks,
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
				assert.Equal(t, "very-popular", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by GitHub project type - only GitHub projects",
			filterExpression: "_.package.projects.exists(p, p.project.type == 1)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "gitlab-project", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITLAB,
										Name: "gitlab-project/repo",
										Url:  "https://gitlab.com/gitlab-project/repo",
									},
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "github-project", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "github-project/repo",
										Url:  "https://github.com/github-project/repo",
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
				assert.Equal(t, "github-project", events[0].Package.GetName())
			},
		},
		{
			name:             "Filter by comprehensive popularity - stars, forks, and contributors",
			filterExpression: "_.package.projects.exists(p, p.stars >= 1000 && p.forks >= 100 && p.contributors >= 10)",
			failOnMatch:      false,
			manifest: &models.PackageManifest{
				Path:      "test/package.json",
				Ecosystem: models.EcosystemNpm,
			},
			setupPackages: func() []*models.Package {
				lowStars := int64(100)
				lowForks := int64(10)
				lowContributors := int64(2)
				highStars := int64(5000)
				highForks := int64(500)
				highContributors := int64(50)
				return []*models.Package{
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "new-project", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "new-project/repo",
										Url:  "https://github.com/new-project/repo",
									},
									Stars:        &lowStars,
									Forks:        &lowForks,
									Contributors: &lowContributors,
								},
							},
						},
					},
					{
						PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "mature-project", "1.0.0"),
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "mature-project/repo",
										Url:  "https://github.com/mature-project/repo",
									},
									Stars:        &highStars,
									Forks:        &highForks,
									Contributors: &highContributors,
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
				assert.Equal(t, "mature-project", events[0].Package.GetName())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create analyzer
			analyzer, err := NewCelFilterV2Analyzer(tc.filterExpression, tc.failOnMatch)
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
			v2Analyzer := analyzer.(*celFilterV2Analyzer)
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

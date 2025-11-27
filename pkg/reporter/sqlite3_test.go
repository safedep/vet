package reporter

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	scorecardv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/scorecard/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/safedep/vet/pkg/models"
)

func TestSqlite3Reporter_ExpectedTables(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "sqlite3_reporter_expected_tables.db")

	_, err := NewSqlite3Reporter(Sqlite3ReporterConfig{
		Path: dbPath,
	})

	assert.NoError(t, err)

	defer os.Remove(dbPath)

	db, err := sql.Open("sqlite3", dbPath)
	assert.NoError(t, err)

	defer db.Close()

	rows, err := db.Query(`
		SELECT name FROM sqlite_master 
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`)
	assert.NoError(t, err)

	defer rows.Close()

	var tableNames []string
	for rows.Next() {
		var name string
		err := rows.Scan(&name)
		assert.NoError(t, err)

		tableNames = append(tableNames, name)
	}

	assert.Contains(t, tableNames, "report_packages")
	assert.Contains(t, tableNames, "report_vulnerabilities")
	assert.Contains(t, tableNames, "report_licenses")
	assert.Contains(t, tableNames, "report_projects")
	assert.Contains(t, tableNames, "report_scorecards")
	assert.Contains(t, tableNames, "report_scorecard_checks")
	assert.Contains(t, tableNames, "report_slsa_provenances")
	assert.Contains(t, tableNames, "report_malwares")
	assert.Contains(t, tableNames, "report_dependencies")
}

func TestSqlite3ReporterPersistence(t *testing.T) {
	// Helper function to create pointers
	ptrString := func(s string) *string { return &s }
	ptrInt64 := func(i int64) *int64 { return &i }

	cases := []struct {
		name     string
		manifest *models.PackageManifest
		assertFn func(t *testing.T, db *sql.DB)
	}{
		{
			name: "basic_package",
			manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					Type:      models.ManifestSourceLocal,
					Namespace: "test",
					Path:      "test",
				},
				Path:      "test",
				Ecosystem: models.EcosystemGo,
				Packages: []*models.Package{
					{
						PackageDetails: lockfile.PackageDetails{
							Ecosystem: lockfile.GoEcosystem,
							Name:      "test",
							Version:   "1.0.0",
						},
						InsightsV2: &packagev1.PackageVersionInsight{},
					},
				},
			},
			assertFn: func(t *testing.T, db *sql.DB) {
				rows, err := db.Query(`SELECT name, version FROM report_packages`)
				assert.NoError(t, err)
				defer rows.Close()
				assert.True(t, rows.Next())

				var name, version string
				err = rows.Scan(&name, &version)
				assert.NoError(t, err)
				assert.Equal(t, "test", name)
				assert.Equal(t, "1.0.0", version)
			},
		},
		{
			name: "vulnerabilities",
			manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					Type:      models.ManifestSourceLocal,
					Namespace: "test",
					Path:      "test",
				},
				Path:      "test",
				Ecosystem: models.EcosystemGo,
				Packages: []*models.Package{
					{
						PackageDetails: lockfile.PackageDetails{
							Ecosystem: lockfile.GoEcosystem,
							Name:      "vulnerable-package",
							Version:   "1.0.0",
						},
						InsightsV2: &packagev1.PackageVersionInsight{
							Vulnerabilities: []*vulnerabilityv1.Vulnerability{
								{
									Id: &vulnerabilityv1.VulnerabilityIdentifier{
										Value: "CVE-2024-1234",
									},
									Summary: "Test vulnerability",
									Aliases: []*vulnerabilityv1.VulnerabilityIdentifier{
										{Value: "GHSA-test-1234"},
									},
									Severities: []*vulnerabilityv1.Severity{
										{
											Risk:  vulnerabilityv1.Severity_RISK_HIGH,
											Type:  vulnerabilityv1.Severity_TYPE_CVSS_V3,
											Score: "7.5",
										},
									},
									PublishedAt: timestamppb.Now(),
									ModifiedAt:  timestamppb.Now(),
								},
							},
						},
					},
				},
			},
			assertFn: func(t *testing.T, db *sql.DB) {
				rows, err := db.Query(`SELECT vulnerability_id, title, severity, cvss_score FROM report_vulnerabilities`)
				assert.NoError(t, err)
				defer rows.Close()
				assert.True(t, rows.Next())

				var vulnID, title, severity string
				var cvssScore float64
				err = rows.Scan(&vulnID, &title, &severity, &cvssScore)
				assert.NoError(t, err)
				assert.Equal(t, "CVE-2024-1234", vulnID)
				assert.Equal(t, "Test vulnerability", title)
				assert.Equal(t, "HIGH", severity)
				assert.Equal(t, 7.5, cvssScore)
			},
		},
		{
			name: "licenses",
			manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					Type:      models.ManifestSourceLocal,
					Namespace: "test",
					Path:      "test",
				},
				Path:      "test",
				Ecosystem: models.EcosystemGo,
				Packages: []*models.Package{
					{
						PackageDetails: lockfile.PackageDetails{
							Ecosystem: lockfile.GoEcosystem,
							Name:      "licensed-package",
							Version:   "1.0.0",
						},
						InsightsV2: &packagev1.PackageVersionInsight{
							Licenses: &packagev1.LicenseMetaList{
								Licenses: []*packagev1.LicenseMeta{
									{
										LicenseId:  "MIT",
										Name:       "MIT License",
										DetailsUrl: "https://spdx.org/licenses/MIT.json",
									},
								},
							},
						},
					},
				},
			},
			assertFn: func(t *testing.T, db *sql.DB) {
				rows, err := db.Query(`SELECT license_id, name, spdx_id, url FROM report_licenses`)
				assert.NoError(t, err)
				defer rows.Close()
				assert.True(t, rows.Next())

				var licenseID, name, spdxID, url string
				err = rows.Scan(&licenseID, &name, &spdxID, &url)
				assert.NoError(t, err)
				assert.Equal(t, "MIT", licenseID)
				assert.Equal(t, "MIT License", name)
				assert.Equal(t, "MIT", spdxID)
				assert.Equal(t, "https://spdx.org/licenses/MIT.json", url)
			},
		},
		{
			name: "project_with_scorecard",
			manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					Type:      models.ManifestSourceLocal,
					Namespace: "test",
					Path:      "test",
				},
				Path:      "test",
				Ecosystem: models.EcosystemGo,
				Packages: []*models.Package{
					{
						PackageDetails: lockfile.PackageDetails{
							Ecosystem: lockfile.GoEcosystem,
							Name:      "scored-package",
							Version:   "1.0.0",
						},
						InsightsV2: &packagev1.PackageVersionInsight{
							ProjectInsights: []*packagev1.ProjectInsight{
								{
									Project: &packagev1.Project{
										Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
										Name: "test/repo",
										Url:  "https://github.com/test/repo",
									},
									Stars: ptrInt64(1000),
									Forks: ptrInt64(200),
									Scorecard: &scorecardv1.Scorecard{
										Date:  "2024-01-01",
										Score: 8.5,
										Repo: &scorecardv1.Scorecard_Repo{
											Name:   "github.com/test/repo",
											Commit: "abc123",
										},
										ScorecardVersion: &scorecardv1.Scorecard_ScorecardVersion{
											Version: "v4.10.2",
										},
										Checks: []*scorecardv1.ScorecardCheck{
											{
												Name:   "Security-Policy",
												Score:  9.0,
												Reason: ptrString("security policy file detected"),
											},
											{
												Name:   "Maintained",
												Score:  10.0,
												Reason: ptrString("30 commits in the last 90 days"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			assertFn: func(t *testing.T, db *sql.DB) {
				// Test project data
				rows, err := db.Query(`SELECT name, url, stars, forks FROM report_projects`)
				assert.NoError(t, err)
				defer rows.Close()
				assert.True(t, rows.Next())

				var projectName, projectURL string
				var stars, forks int32
				err = rows.Scan(&projectName, &projectURL, &stars, &forks)
				assert.NoError(t, err)
				assert.Equal(t, "test/repo", projectName)
				assert.Equal(t, "https://github.com/test/repo", projectURL)
				assert.Equal(t, int32(1000), stars)
				assert.Equal(t, int32(200), forks)
				rows.Close()

				// Test scorecard data
				rows, err = db.Query(`SELECT score, scorecard_version, repo_name, repo_commit, date FROM report_scorecards`)
				assert.NoError(t, err)
				defer rows.Close()
				assert.True(t, rows.Next())

				var score float32
				var version, repoName, repoCommit, date string
				err = rows.Scan(&score, &version, &repoName, &repoCommit, &date)
				assert.NoError(t, err)
				assert.Equal(t, float32(8.5), score)
				assert.Equal(t, "v4.10.2", version)
				assert.Equal(t, "github.com/test/repo", repoName)
				assert.Equal(t, "abc123", repoCommit)
				assert.Equal(t, "2024-01-01", date)
				rows.Close()

				// Test scorecard checks
				rows, err = db.Query(`SELECT name, score, reason FROM report_scorecard_checks ORDER BY name`)
				assert.NoError(t, err)
				defer rows.Close()

				// First check
				assert.True(t, rows.Next())
				var checkName, reason string
				var checkScore float32
				err = rows.Scan(&checkName, &checkScore, &reason)
				assert.NoError(t, err)
				assert.Equal(t, "Maintained", checkName)
				assert.Equal(t, float32(10.0), checkScore)
				assert.Equal(t, "30 commits in the last 90 days", reason)

				// Second check
				assert.True(t, rows.Next())
				err = rows.Scan(&checkName, &checkScore, &reason)
				assert.NoError(t, err)
				assert.Equal(t, "Security-Policy", checkName)
				assert.Equal(t, float32(9.0), checkScore)
				assert.Equal(t, "security policy file detected", reason)
			},
		},
		{
			name: "slsa_provenance",
			manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					Type:      models.ManifestSourceLocal,
					Namespace: "test",
					Path:      "test",
				},
				Path:      "test",
				Ecosystem: models.EcosystemGo,
				Packages: []*models.Package{
					{
						PackageDetails: lockfile.PackageDetails{
							Ecosystem: lockfile.GoEcosystem,
							Name:      "provenance-package",
							Version:   "1.0.0",
						},
						InsightsV2: &packagev1.PackageVersionInsight{
							SlsaProvenances: []*packagev1.PackageVersionSlsaProvenance{
								{
									SourceRepository: "https://github.com/test/repo",
									CommitSha:        "abc123def456",
									Url:              "https://github.com/test/repo/attestations/1234",
									Verified:         true,
								},
								{
									SourceRepository: "https://github.com/test/repo",
									CommitSha:        "def456ghi789",
									Url:              "https://github.com/test/repo/attestations/5678",
									Verified:         false,
								},
							},
						},
					},
				},
			},
			assertFn: func(t *testing.T, db *sql.DB) {
				rows, err := db.Query(`SELECT source_repository, commit_sha, url, verified FROM report_slsa_provenances ORDER BY verified DESC`)
				assert.NoError(t, err)
				defer rows.Close()

				// First provenance (verified)
				assert.True(t, rows.Next())
				var sourceRepo, commitSha, url string
				var verified bool
				err = rows.Scan(&sourceRepo, &commitSha, &url, &verified)
				assert.NoError(t, err)
				assert.Equal(t, "https://github.com/test/repo", sourceRepo)
				assert.Equal(t, "abc123def456", commitSha)
				assert.Equal(t, "https://github.com/test/repo/attestations/1234", url)
				assert.True(t, verified)

				// Second provenance (unverified)
				assert.True(t, rows.Next())
				err = rows.Scan(&sourceRepo, &commitSha, &url, &verified)
				assert.NoError(t, err)
				assert.Equal(t, "https://github.com/test/repo", sourceRepo)
				assert.Equal(t, "def456ghi789", commitSha)
				assert.Equal(t, "https://github.com/test/repo/attestations/5678", url)
				assert.False(t, verified)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "sqlite3_reporter_persistence.db")
			reporter, err := NewSqlite3Reporter(Sqlite3ReporterConfig{
				Path: dbPath,
			})

			assert.NoError(t, err)

			reporter.AddManifest(tc.manifest)

			err = reporter.Finish()
			assert.NoError(t, err)

			db, err := sql.Open("sqlite3", dbPath)
			assert.NoError(t, err)

			defer db.Close()

			tc.assertFn(t, db)
		})
	}
}

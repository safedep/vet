package reporter

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"

	_ "github.com/mattn/go-sqlite3"
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
	cases := []struct {
		name     string
		manifest *models.PackageManifest
		assertFn func(t *testing.T, db *sql.DB)
	}{
		{
			name: "basic",
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
				rows, err := db.Query(`SELECT * FROM report_packages`)
				assert.NoError(t, err)

				defer rows.Close()
				assert.True(t, rows.Next())
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

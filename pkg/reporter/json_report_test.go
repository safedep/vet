package reporter

import (
	"bytes"
	"os"
	"testing"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/dry/api/pb"
	"github.com/stretchr/testify/assert"

	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
)

// We are going to expose this as a contract eventually for other tools
// so it is important that we have appropriate test cases maintained
// for this reporter
func TestJsonRepoGenerator(t *testing.T) {
	cases := []struct {
		name string

		manifests []*models.PackageManifest
		events    []*analyzer.AnalyzerEvent
		assertFn  func(t *testing.T, report *jsonreportspec.Report)
	}{
		{
			"Verify sanity of test",
			[]*models.PackageManifest{
				{
					Source: models.PackageManifestSource{
						Type:        models.ManifestSourceLocal,
						Namespace:   "/namespace/1",
						Path:        "sample-path",
						DisplayPath: "/tmp/sample/display/path/does/not/matter",
					},
					Path:      "/real/path",
					Ecosystem: models.EcosystemGo,
					Packages: []*models.Package{
						{
							PackageDetails: lockfile.PackageDetails{
								Name:    "golib1",
								Version: "0.1.2",
							},
						},
					},
				},
			},
			[]*analyzer.AnalyzerEvent{},
			func(t *testing.T, report *jsonreportspec.Report) {
				assert.Equal(t, 1, len(report.Manifests))
				assert.Equal(t, "sample-path", report.Manifests[0].Path)
				assert.Equal(t, "/namespace/1", report.Manifests[0].Namespace)

				assert.Equal(t, "/namespace/1/sample-path", report.Manifests[0].DisplayPath)
				assert.Equal(t, string(models.ManifestSourceLocal), report.Manifests[0].SourceType)
				assert.Equal(t, 1, len(report.Packages))
				assert.Equal(t, "golib1", report.Packages[0].GetPackage().GetName())
				assert.Equal(t, "0.1.2", report.Packages[0].GetPackage().GetVersion())
			},
		},
		{
			"Verify GitHub manifest",
			[]*models.PackageManifest{
				{
					Source: models.PackageManifestSource{
						Type:        models.ManifestSourceGitRepository,
						Namespace:   "/namespace/1",
						Path:        "sample-path",
						DisplayPath: "/tmp/sample/display/path",
					},
					Path:      "/real/path",
					Ecosystem: models.EcosystemGo,
					Packages: []*models.Package{
						{
							PackageDetails: lockfile.PackageDetails{
								Name:    "golib1",
								Version: "0.1.2",
							},
							MalwareAnalysis: &models.MalwareAnalysisResult{
								AnalysisId:   "TESTID",
								IsSuspicious: true,
								IsMalware:    false,
							},
						},
					},
				},
			},
			[]*analyzer.AnalyzerEvent{},
			func(t *testing.T, report *jsonreportspec.Report) {
				assert.Equal(t, "/tmp/sample/display/path", report.Manifests[0].DisplayPath)
			},
		},
		{
			"Verify excluded malware is omitted from report",
			[]*models.PackageManifest{
				{
					Source: models.PackageManifestSource{
						Type:        models.ManifestSourceLocal,
						Namespace:   "/namespace/1",
						Path:        "requirements.txt",
						DisplayPath: "/tmp/sample/display/path",
					},
					Path:      "/real/path",
					Ecosystem: models.EcosystemPyPI,
					Packages: []*models.Package{
						{
							PackageDetails: lockfile.PackageDetails{
								Name:    "easyclaw-installer",
								Version: "0.7.0",
							},
							MalwareAnalysis: &models.MalwareAnalysisResult{
								AnalysisId: "TESTID",
								Report:     &malysisv1.Report{},
								Exclusion: &models.MalwareAnalysisExclusion{
									ExclusionID: "exc-1",
									Reason:      "tenant-approved investigation",
								},
							},
						},
					},
				},
			},
			[]*analyzer.AnalyzerEvent{},
			func(t *testing.T, report *jsonreportspec.Report) {
				assert.Len(t, report.Packages, 1)
				assert.Empty(t, report.Packages[0].MalwareInfo)
			},
		},
		{
			"Verify malware result without report is omitted",
			[]*models.PackageManifest{
				{
					Source: models.PackageManifestSource{
						Type:        models.ManifestSourceLocal,
						Namespace:   "/namespace/1",
						Path:        "requirements.txt",
						DisplayPath: "/tmp/sample/display/path",
					},
					Path:      "/real/path",
					Ecosystem: models.EcosystemPyPI,
					Packages: []*models.Package{
						{
							PackageDetails: lockfile.PackageDetails{
								Name:    "unknown-malware-result",
								Version: "0.1.0",
							},
							MalwareAnalysis: &models.MalwareAnalysisResult{
								AnalysisId: "TESTID",
							},
						},
					},
				},
			},
			[]*analyzer.AnalyzerEvent{},
			func(t *testing.T, report *jsonreportspec.Report) {
				assert.Len(t, report.Packages, 1)
				assert.Empty(t, report.Packages[0].MalwareInfo)
			},
		},
	}

	tmpFile, err := os.CreateTemp("", "vet-json-report-test-*")
	if err != nil {
		panic(err)
	}

	_ = tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r, err := NewJsonReportGenerator(JsonReportingConfig{
				Path: tmpFile.Name(),
				Tool: ToolMetadata{
					Name:           "vet",
					Version:        "latest",
					InformationURI: "https://github.com/safedep/vet",
					VendorName:     "SafeDep",
				},
			})

			assert.Nil(t, err)

			for _, m := range test.manifests {
				// We need to fix the manifest reference for each package
				for _, pkg := range m.Packages {
					pkg.Manifest = m
				}

				r.AddManifest(m)
			}

			for _, e := range test.events {
				r.AddAnalyzerEvent(e)
			}

			err = r.Finish()
			assert.Nil(t, err)

			data, err := os.ReadFile(tmpFile.Name())
			assert.Nil(t, err)

			var report jsonreportspec.Report
			err = pb.FromJson(bytes.NewReader(data), &report)
			assert.Nil(t, err)

			test.assertFn(t, &report)
		})
	}
}

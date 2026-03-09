package reporter

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/models"
)

func TestMarkdownReportIncludesExcludedPackages(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "vet-markdown-report-test-*")
	if err != nil {
		t.Fatal(err)
	}

	_ = tmpFile.Close()
	t.Cleanup(func() {
		err := os.Remove(tmpFile.Name())
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("failed to remove temp file: %v", err)
		}
	})

	reporter, err := NewMarkdownReportGenerator(MarkdownReportingConfig{
		Path: tmpFile.Name(),
	})
	assert.NoError(t, err)

	manifest := &models.PackageManifest{
		Source: models.PackageManifestSource{
			Type:        models.ManifestSourceLocal,
			Namespace:   "/workspace",
			Path:        "requirements.txt",
			DisplayPath: "/workspace/requirements.txt",
		},
		Path:      "/workspace/requirements.txt",
		Ecosystem: models.EcosystemPyPI,
		Packages: []*models.Package{
			{
				PackageDetails: lockfile.PackageDetails{
					Name:    "easyclaw-installer",
					Version: "0.7.0",
				},
				MalwareAnalysis: &models.MalwareAnalysisResult{
					AnalysisId: "ANALYSIS-ID",
					Exclusion: &models.MalwareAnalysisExclusion{
						ExclusionID: "exc-1",
						Reason:      "tenant-approved investigation",
					},
				},
			},
		},
	}

	for _, pkg := range manifest.Packages {
		pkg.Manifest = manifest
	}

	reporter.AddManifest(manifest)
	assert.NoError(t, reporter.Finish())

	data, err := os.ReadFile(tmpFile.Name())
	assert.NoError(t, err)

	output := string(data)
	assert.Contains(t, output, "## Malware Query Exclusions")
	assert.Contains(t, output, "easyclaw-installer@0.7.0")
	assert.Contains(t, output, "tenant-approved investigation")
	assert.Contains(t, output, "| /workspace/requirements.txt | PyPI | 1 | 0 |")
}

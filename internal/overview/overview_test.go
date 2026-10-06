package overview

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestRead(t *testing.T) {
	s := plugintest.SampleReport()
	s.ManifestList[0].Packages[0].Change = model.ChangeAdded
	s.ManifestList[0].Packages[1].Insight = &model.Insight{LatestVersion: "1.3.1"}
	s.ManifestList = append(s.ManifestList, &model.Manifest{ID: "w", Path: ".github/workflows/ci.yml", Kind: model.ManifestKindWorkflow, Change: model.ChangeModified})
	pad := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0")}
	vuln := finding.ForPackage(finding.Meta{
		ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "GHSA-1",
	}, "package-lock.json", pad, finding.Key{Discriminator: "GHSA-1"})
	s.FindingList = append(s.FindingList, &vuln)
	got, err := Read(context.Background(), s)
	require.NoError(t, err)
	assert.Equal(t, Changes{Packages: 1, Workflows: 1, Unchanged: 1}, got.Changes)
	assert.Len(t, got.Diagnostics, 1)
	assert.Len(t, got.Suppressed, 1)
	assert.Equal(t, map[model.PackageKey]string{model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0").Key(): "1.3.1"}, got.Latest)
	var severities []finding.Severity
	for _, f := range got.Findings {
		severities = append(severities, f.Severity)
	}
	assert.Equal(t, []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium}, severities,
		"the most severe first, and no suppressed finding")
}

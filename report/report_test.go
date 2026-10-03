package report

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

func testFinding(sev finding.Severity) *finding.Finding {
	f := finding.ForManifest(finding.Meta{ControlID: "c", Family: finding.FamilyLockfile, Severity: sev, Title: "t"},
		"package-lock.json", model.EcosystemNpm, finding.Key{})
	return &f
}

func TestRecordValidate(t *testing.T) {
	cases := []struct {
		name    string
		r       Record
		wantErr bool
	}{
		{"manifest", ManifestRecord(&model.Manifest{ID: "m1", Path: "a"}), false},
		{"package", PackageRecord(&PackageEntry{PURL: "pkg:npm/a@1"}), false},
		{"inventory", InventoryRecord(&InventoryItem{Kind: InventoryMCPServer, Name: "x"}), false},
		{"finding", FindingRecord(testFinding(finding.SeverityHigh)), false},
		{"diagnostic", DiagnosticRecord(&Diagnostic{Level: DiagnosticWarning, Code: "c"}), false},
		{"empty", Record{Kind: KindFinding}, true},
		{"mismatch", Record{Kind: KindPackage, Diagnostic: &Diagnostic{}}, true},
		{"two fields", Record{Kind: KindPackage, Package: &PackageEntry{}, Diagnostic: &Diagnostic{}}, true},
		{"invalid finding", Record{Kind: KindFinding, Finding: &finding.Finding{}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSummaryAdd(t *testing.T) {
	var s Summary
	s.Add(ManifestRecord(&model.Manifest{}))
	s.Add(PackageRecord(&PackageEntry{}))
	s.Add(PackageRecord(&PackageEntry{}))
	s.Add(FindingRecord(testFinding(finding.SeverityHigh)))
	s.Add(FindingRecord(testFinding(finding.SeverityHigh)))
	suppressed := testFinding(finding.SeverityCritical)
	suppressed.Suppression = &finding.Suppression{Reason: "reviewed"}
	s.Add(FindingRecord(suppressed))
	s.Add(DiagnosticRecord(&Diagnostic{}))

	assert.Equal(t, 1, s.Manifests)
	assert.Equal(t, 2, s.Packages)
	assert.Equal(t, 2, s.Findings)
	assert.Equal(t, 1, s.Suppressed)
	assert.Equal(t, 1, s.Diagnostics)
	assert.Equal(t, 2, s.BySeverity[finding.SeverityHigh])
	assert.Equal(t, 0, s.BySeverity[finding.SeverityCritical])
	assert.Equal(t, 2, s.ByFamily[finding.FamilyLockfile])
}

func TestPackageEntryJSONFlattens(t *testing.T) {
	e := PackageEntry{
		PURL:        "pkg:npm/a@1.0.0",
		ManifestIDs: []string{"m1"},
		Package:     model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1.0.0"}, Direct: true},
	}
	b, err := json.Marshal(e)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, "pkg:npm/a@1.0.0", m["purl"])
	assert.Equal(t, true, m["direct"])
	assert.Contains(t, m, "id")

	var back PackageEntry
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, e, back)
}

func TestCompareCapabilitiesPutsAIThenWeakCryptoFirst(t *testing.T) {
	caps := []*Capability{
		{ID: "net.http", Tags: []string{"network"}},
		{ID: "crypto.sha256", Tags: []string{TagCrypto, "hash"}},
		{ID: "openai.client", Tags: []string{TagAI, "llm"}},
		{ID: "crypto.md5", Tags: []string{TagCrypto, "hash", TagWeak}},
		{ID: "anthropic.client", Tags: []string{TagAI, "llm"}},
	}
	slices.SortFunc(caps, CompareCapabilities)
	var ids []string
	for _, c := range caps {
		ids = append(ids, c.ID)
	}
	assert.Equal(t, []string{"anthropic.client", "openai.client", "crypto.md5", "crypto.sha256", "net.http"}, ids)
	assert.Equal(t, CapabilityOther, caps[4].Kind())
}

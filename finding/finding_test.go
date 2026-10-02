package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

var meta = Meta{
	ControlID: "malware",
	Family:    FamilyMalware,
	Severity:  SeverityCritical,
	Title:     "Malicious package",
}

func pkg(version string, line int) *model.Package {
	return &model.Package{
		ID:   model.PackageID{Ecosystem: model.EcosystemNpm, Name: "evil", Version: version},
		Line: line,
	}
}

func TestConstructorsKeepOneSubject(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		kind SubjectKind
	}{
		{"package", ForPackage(meta, "package-lock.json", pkg("1.0.0", 10)), SubjectPackage},
		{"file", ForFile(meta, Locus{Path: ".github/workflows/ci.yml", StartLine: 3}), SubjectFile},
		{"manifest", ForManifest(meta, "package-lock.json", model.EcosystemNpm), SubjectManifest},
		{"application", ForApplication(meta, "apps/agent", "sig-1"), SubjectApplication},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.f.Validate())
			assert.Equal(t, tc.kind, tc.f.Subject.Kind)
			assert.Regexp(t, `^f-[0-9a-f]{16}$`, tc.f.ID)
			assert.Equal(t, ConfidenceHigh, tc.f.Confidence)
		})
	}
}

func TestForPackageFields(t *testing.T) {
	p := pkg("1.0.0", 10)
	p.Direct = true
	p.Change = model.ChangeAdded
	f := ForPackage(meta, "package-lock.json", p)
	assert.Equal(t, "pkg:npm/evil@1.0.0", f.Subject.Package.PURL)
	assert.True(t, f.Subject.Package.Direct)
	assert.Equal(t, model.ChangeAdded, f.Change)
	require.NotNil(t, f.Locus)
	assert.Equal(t, 10, f.Locus.StartLine)
}

func TestValidate(t *testing.T) {
	ok := ForManifest(Meta{ControlID: "c", Family: FamilyLockfile, Severity: SeverityHigh, Title: "t"}, "a.lock", model.EcosystemNpm)
	require.NoError(t, ok.Validate())

	cases := []struct {
		name   string
		mutate func(f *Finding)
	}{
		{"no id", func(f *Finding) { f.ID = "" }},
		{"no control", func(f *Finding) { f.ControlID = "" }},
		{"bad severity", func(f *Finding) { f.Severity = "urgent" }},
		{"bad family", func(f *Finding) { f.Family = "x" }},
		{"bad confidence", func(f *Finding) { f.Confidence = "sure" }},
		{"bad change", func(f *Finding) { f.Change = "MOVED" }},
		{"two subjects", func(f *Finding) { f.Subject.File = &FileSubject{Path: "x"} }},
		{"no subject", func(f *Finding) { f.Subject.Manifest = nil }},
		{"kind mismatch", func(f *Finding) { f.Subject.Kind = SubjectFile }},
		{"no title", func(f *Finding) { f.Title = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ok
			m := *ok.Subject.Manifest
			f.Subject.Manifest = &m
			tc.mutate(&f)
			assert.Error(t, f.Validate())
		})
	}
}

func TestSeverity(t *testing.T) {
	s, err := ParseSeverity(" HIGH ")
	require.NoError(t, err)
	assert.Equal(t, SeverityHigh, s)
	assert.True(t, SeverityCritical.AtLeast(SeverityHigh))
	assert.False(t, SeverityLow.AtLeast(SeverityHigh))
	assert.Equal(t, []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}, Severities())
	_, err = ParseSeverity("urgent")
	assert.Error(t, err)
}

func TestFamilies(t *testing.T) {
	for _, f := range Families() {
		assert.True(t, f.Valid(), f)
	}
	assert.False(t, Family("other").Valid())
}

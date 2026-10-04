package render

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

func TestSubjectAndWhere(t *testing.T) {
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "@s/x\x1b[31m", "1.0.0"), Line: 3}
	pkg := finding.ForPackage(finding.Meta{ControlID: "c", Family: finding.FamilyMalware, Severity: finding.SeverityLow, Title: "t"}, "a/package-lock.json", p, finding.Key{})
	file := finding.ForFile(finding.Meta{ControlID: "c", Family: finding.FamilyWorkflow, Severity: finding.SeverityLow, Title: "t"},
		finding.Locus{Path: "ci.yml"}, finding.Key{})
	action := finding.ForFile(finding.Meta{ControlID: "c", Family: finding.FamilyWorkflow, Severity: finding.SeverityLow, Title: "t"},
		finding.Locus{Path: "ci.yml", StartLine: 8}, finding.Key{})
	action.Subject.File.Element = "actions/setup-node@main"
	man := finding.ForManifest(finding.Meta{ControlID: "c", Family: finding.FamilyLockfile, Severity: finding.SeverityLow, Title: "t"}, "go.mod", model.EcosystemGo, finding.Key{})

	cases := []struct {
		name               string
		f                  finding.Finding
		subject, id, where string
	}{
		{name: "package", f: pkg, subject: `npm/@s/x\x1b[31m@1.0.0`, id: `pkg:npm/%40s/x%1B%5B31m@1.0.0`, where: "a/package-lock.json:3"},
		{name: "file", f: file, subject: "ci.yml", id: "ci.yml", where: "ci.yml"},
		{name: "workflow element", f: action, subject: "actions/setup-node@main", id: "ci.yml", where: "ci.yml:8"},
		{name: "manifest", f: man, subject: "go.mod", id: "go.mod", where: "go.mod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.subject, Subject(&tc.f))
			assert.Equal(t, tc.id, SubjectID(&tc.f))
			assert.Equal(t, tc.where, Where(&tc.f))
			assert.NotContains(t, Subject(&tc.f), "\x1b", "terminal escapes from the scanned code are escaped")
		})
	}
}

func TestTitleDropsTheSubject(t *testing.T) {
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "django", "2.2.0")}
	pkg := func(title string) finding.Finding {
		return finding.ForPackage(finding.Meta{ControlID: "c", Family: finding.FamilyVulnerability, Severity: finding.SeverityLow, Title: title}, "requirements.txt", p, finding.Key{})
	}
	file := func(title, element string) finding.Finding {
		f := finding.ForFile(finding.Meta{ControlID: "c", Family: finding.FamilyWorkflow, Severity: finding.SeverityLow, Title: title}, finding.Locus{Path: "ci.yml"}, finding.Key{})
		f.Subject.File.Element = element
		return f
	}
	cases := []struct {
		name string
		f    finding.Finding
		want string
	}{
		{name: "vulnerability", f: pkg("GHSA-hmr4-m2h5-33qx in pypi/django@2.2.0: SQL injection in Django"), want: "GHSA-hmr4-m2h5-33qx: SQL injection in Django"},
		{name: "no package in the title", f: pkg("Malicious package"), want: "Malicious package"},
		{name: "workflow element", f: file("actions/checkout@v4 is not pinned to a commit SHA", "actions/checkout@v4"), want: "is not pinned to a commit SHA"},
		{name: "element not at the start", f: file("Job build asks for write-all permissions", "permissions: write-all"), want: "Job build asks for write-all permissions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Title(&tc.f))
		})
	}
}

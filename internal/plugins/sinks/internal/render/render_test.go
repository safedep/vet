package render

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

func TestSubjectAndWhere(t *testing.T) {
	p := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Namespace: "@s", Name: "x\x1b[31m", Version: "1.0.0"}, Line: 3}
	pkg := finding.ForPackage(finding.Meta{ControlID: "c", Family: finding.FamilyMalware, Severity: finding.SeverityLow, Title: "t"}, "a/package-lock.json", p, finding.Key{})
	file := finding.ForFile(finding.Meta{ControlID: "c", Family: finding.FamilyWorkflow, Severity: finding.SeverityLow, Title: "t"},
		finding.Locus{Path: "ci.yml"}, finding.Key{})
	man := finding.ForManifest(finding.Meta{ControlID: "c", Family: finding.FamilyLockfile, Severity: finding.SeverityLow, Title: "t"}, "go.mod", model.EcosystemGo, finding.Key{})

	cases := []struct {
		name               string
		f                  finding.Finding
		subject, id, where string
	}{
		{name: "package", f: pkg, subject: `npm/@s/x\x1b[31m@1.0.0`, id: `pkg:npm/%40s/x%1B%5B31m@1.0.0`, where: "a/package-lock.json:3"},
		{name: "file", f: file, subject: "ci.yml", id: "ci.yml", where: "ci.yml"},
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

package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

func TestAnnotateUsage(t *testing.T) {
	used := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1.0.0"}, Usage: &model.Usage{Imported: true, Files: []string{"src/x.js", "src/y.js"}}}
	unused := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "b", Version: "1.0.0"}, Usage: &model.Usage{}}
	unknown := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "c", Version: "1.0.0"}}
	once := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "d", Version: "1.0.0"}, Usage: &model.Usage{Imported: true, Files: []string{"index.js"}}}
	many := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "f", Version: "1.0.0"}, Usage: &model.Usage{Imported: true, Files: []string{"a.js", "b.js", "c.js"}}}
	noFiles := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "e", Version: "1.0.0"}, Usage: &model.Usage{Imported: true}}
	m := &model.Manifest{Path: "package-lock.json", Packages: []*model.Package{used, unused, unknown, once, many, noFiles}}
	meta := finding.Meta{ControlID: "x", Family: finding.FamilyMalware, Severity: finding.SeverityHigh, Title: "t"}

	cases := []struct {
		pkg  *model.Package
		want []finding.Evidence
	}{
		{used, []finding.Evidence{{Source: "codeusage", Summary: "src/x.js and 1 other file import the package."}}},
		{unused, []finding.Evidence{{Source: "codeusage", Summary: "No source file of the project imports the package."}}},
		{unknown, nil},
		{once, []finding.Evidence{{Source: "codeusage", Summary: "index.js imports the package."}}},
		{many, []finding.Evidence{{Source: "codeusage", Summary: "a.js and 2 other files import the package."}}},
		{noFiles, []finding.Evidence{{Source: "codeusage", Summary: "The project imports the package."}}},
	}
	for _, tc := range cases {
		f := finding.ForPackage(meta, m.Path, tc.pkg, finding.Key{})
		annotateUsage(&f, m)
		assert.Equal(t, tc.want, f.Evidence, tc.pkg.ID.Name)
	}
	file := finding.ForFile(meta, finding.Locus{Path: "x"}, finding.Key{})
	annotateUsage(&file, m)
	assert.Empty(t, file.Evidence)
}

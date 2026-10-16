package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

func TestAnnotateUsage(t *testing.T) {
	used := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0"), Enrichment: model.Enrichment{Usage: &model.Usage{Imported: true, Files: []string{"src/x.js", "src/y.js"}}}}
	unused := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "b", "1.0.0"), Enrichment: model.Enrichment{Usage: &model.Usage{}}}
	unknown := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "c", "1.0.0")}
	once := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "d", "1.0.0"), Enrichment: model.Enrichment{Usage: &model.Usage{Imported: true, Files: []string{"index.js"}}}}
	many := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "f", "1.0.0"), Enrichment: model.Enrichment{Usage: &model.Usage{Imported: true, Files: []string{"a.js", "b.js", "c.js"}}}}
	noFiles := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "e", "1.0.0"), Enrichment: model.Enrichment{Usage: &model.Usage{Imported: true}}}
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
		assert.Equal(t, tc.want, f.Evidence, tc.pkg.ID.RawName())
	}
	file := finding.ForFile(meta, finding.Locus{Path: "x"}, finding.Key{})
	annotateUsage(&file, m)
	assert.Empty(t, file.Evidence)
}

type describedControl struct {
	infos    []plugin.ControlInfo
	findings []finding.Finding
}

func (c describedControl) Controls() []plugin.ControlInfo { return c.infos }

func (c describedControl) Evaluate(context.Context, *model.Manifest, plugin.State) ([]finding.Finding, error) {
	return c.findings, nil
}

func TestValidSetsTheAttackFromTheControlInfo(t *testing.T) {
	meta := func(id string) finding.Meta {
		return finding.Meta{ControlID: id, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical, Title: "t"}
	}
	claimed := finding.ForFile(meta("note"), finding.Locus{Path: "b.js"}, finding.Key{})
	claimed.Attack = &finding.Attack{}
	c := describedControl{
		infos: []plugin.ControlInfo{{ID: "payload", Attack: true}, {ID: "note"}},
		findings: []finding.Finding{
			finding.ForFile(meta("payload"), finding.Locus{Path: "a.js"}, finding.Key{}),
			claimed,
		},
	}
	r := &run{diags: newDiagnostics(), attacks: attacksOf([]Control{{ID: "p", Plugin: c}})}
	fs, err := c.Evaluate(context.Background(), nil, nil)
	require.NoError(t, err)
	got := r.valid("p", "m", fs, nil)
	require.Len(t, got, 2)
	assert.NotNil(t, got[0].Attack, "the finding of an attack control is an attack")
	assert.Nil(t, got[1].Attack, "a control cannot mark its own finding as an attack")
}

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

func TestPackageOfMatchesByIdentity(t *testing.T) {
	a := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "/", "1.0.0")}
	b := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "//", "1.0.0")}
	django := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "django", "2.2")}
	require.Empty(t, a.ID.PURL(), "the test needs names that form no PURL")
	require.Empty(t, b.ID.PURL(), "the test needs names that form no PURL")
	m := &model.Manifest{Path: "package-lock.json", Packages: []*model.Package{a, b, django}}

	cases := []struct {
		name string
		of   *model.Package
		want *model.Package
	}{
		{"two packages with no PURL stay apart", &model.Package{ID: b.ID}, b},
		{"another spelling of a PyPI package", &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "Django", "2.2.0")}, django},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := finding.ForPackage(finding.Meta{ControlID: "c", Family: finding.FamilyHygiene, Severity: finding.SeverityLow, Title: "t"}, m.Path, tc.of, finding.Key{})
			assert.Same(t, tc.want, packageOf(m, &f))
		})
	}
}

package report

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/reportdoc"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

func TestComparePackagesByIdentity(t *testing.T) {
	doc := func(ids ...model.PackageVersion) *reportdoc.Doc {
		d := &report.Document{Records: []report.Record{{Kind: report.KindManifest, Manifest: &model.Manifest{ID: "m", Path: "x"}}}}
		for _, id := range ids {
			d.Records = append(d.Records, report.Record{Kind: report.KindPackage, Package: &report.PackageEntry{
				PURL: id.PURL(), ManifestIDs: []string{"m"}, Package: model.Package{ID: id},
			}})
		}
		return reportdoc.FromDocument(d)
	}
	slash := model.MustPackageVersion(model.EcosystemNpm, "/", "1.0.0")
	slashes := model.MustPackageVersion(model.EcosystemNpm, "//", "1.0.0")
	require.Empty(t, slash.PURL(), "the test needs names that form no PURL")
	require.Empty(t, slashes.PURL(), "the test needs names that form no PURL")

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	d, err := compare(cmd,
		doc(model.MustPackageVersion(model.EcosystemPyPI, "Django", "2.2.0"), slash),
		doc(model.MustPackageVersion(model.EcosystemPyPI, "django", "2.2"), slash, slashes))
	require.NoError(t, err)
	assert.Equal(t, []string{"npm///@1.0.0"}, d.PackagesAdded)
	assert.Empty(t, d.PackagesRemoved, "another spelling of a PyPI package is the same package")
}

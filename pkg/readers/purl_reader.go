package readers

import (
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"
)

type purlReader struct {
	purl string
}

func NewPurlReader(purl string) (PackageManifestReader, error) {
	return &purlReader{purl: purl}, nil
}

func (p *purlReader) Name() string {
	return "PURL Reader"
}

func (p *purlReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error) error {
	parsedPurl, err := purl.ParsePackageUrl(p.purl)
	if err != nil {
		return err
	}

	pd := parsedPurl.GetPackageDetails()
	pm := models.NewPackageManifestFromPurl(p.purl, string(pd.Ecosystem))

	pm.AddPackage(&models.Package{
		PackageDetails: pd,
		Manifest:       pm,
	})

	return handler(pm, NewManifestModelReader(pm))
}

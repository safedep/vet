package packagefile

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/package-url/packageurl-go"
	"github.com/safedep/vet/pkg/common/logger"
	sbom_utils "github.com/safedep/vet/pkg/common/utils/sbom"
	"github.com/spdx/tools-golang/spdx"
)

// Source from which PackageDetails will be created such as spdx, cyclone_dx, packagefile
type SourceType string

const (
	SPDX_SRC_TYPE        = "spdx"
	CYCLONE_DX_SRC_TYPE  = "cyclone_dx"
	SOURCE_FILE_SRC_TYPE = "source_file"
)

type PackageDetailsDoc struct {
	PackageDetails []*PackageDetails `json:"package_details"`
	SourceType     string            `json:"source_type"`
	SpdxDoc        *spdx.Document    `json:"spdx_doc,omitempty"`
	CycloneDxDoc   *cdx.BOM          `json:"cylcone_dx_doc,omitempty"`
}

/*
PackageDetails
*/
type PackageDetails struct {
	Name  string `json:"name"`
	Group string `json:"group"` //Namespace or Group if available
	// Version extracted. It can be min, max or exact. It can be empty or exact version string
	Version string `json:"version"`
	// Specs specific version string with operators
	VersionExpr  string             `json:"version_expression"` // Version expression
	Commit       string             `json:"commit,omitempty"`
	Ecosystem    lockfile.Ecosystem `json:"ecosystem,omitempty"`
	CompareAs    lockfile.Ecosystem `json:"compare_as,omitempty"`
	SpdxRef      *spdx.Package      `json:"spdx_ref,omitempty"`
	CycloneDxRef *cdx.Component     `json:"cylcone_dx_ref,omitempty"`
}

// Parse from Purl if available. It is a reliable parsing technique
func ParsePackageFromPurl(purl string) (*PackageDetails, error) {
	instance, err := packageurl.FromString(purl)
	if err != nil {
		return nil, err
	}
	ecosysystem, err := sbom_utils.PurlTypeToLockfileEcosystem(instance.Type)
	if err != nil {
		logger.Debugf("Unknown ecosystem type: %s", instance.Type)
		return nil, err
	}
	pd := &PackageDetails{
		Name:      instance.Name,
		Group:     instance.Namespace,
		Version:   instance.Version,
		Ecosystem: ecosysystem,
		CompareAs: ecosysystem,
	}
	return pd, nil
}

/*
Convert to osv-scanner/pkg/lockfile PackageDetails
*/
func (pd *PackageDetails) Convert2LockfilePackageDetails() *lockfile.PackageDetails {
	name := pd.createOssScannerPackageDetailName()
	return &lockfile.PackageDetails{
		Name:      name,
		Version:   pd.Version,
		Ecosystem: pd.Ecosystem,
		CompareAs: pd.CompareAs,
	}
}

func (pd *PackageDetails) createOssScannerPackageDetailName() string {
	name := pd.Name
	if pd.Group != "" {
		switch pd.Ecosystem {
		case lockfile.GoEcosystem:
			name = fmt.Sprintf("%s/%s", pd.Group, pd.Name)
		case lockfile.NpmEcosystem:
			name = fmt.Sprintf("%s/%s", pd.Group, pd.Name)
		default:
			name = fmt.Sprintf("%s:%s", pd.Group, pd.Name)
		}
	}
	return name
}

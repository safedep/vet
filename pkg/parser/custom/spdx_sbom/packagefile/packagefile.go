package packagefile

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/lockfile"
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
	Name string `json:"name"`
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

/*
Convert to osv-scanner/pkg/lockfile PackageDetails
*/
func (pd *PackageDetails) Convert2LockfilePackageDetails() *lockfile.PackageDetails {
	return &lockfile.PackageDetails{
		Name:      pd.Name,
		Version:   pd.Version,
		Ecosystem: pd.Ecosystem,
		CompareAs: pd.CompareAs,
	}
}

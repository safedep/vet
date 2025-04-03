package data

import (
	"embed"
	"encoding/json"
)

// Fetched from the SPDX license list - https://spdx.org/licenses/licenses.json
// using script - ./scripts/download_spdx_licenses.sh

//go:embed licenses.json
var licensesFile embed.FS

type SpdxLicense struct {
	Reference string `json:"reference"`
	Name      string `json:"name,omitempty"`
	LicenseId string `json:"licenseId,omitempty"`
}

type spdxLicensesJson struct {
	LicenseListVersion string        `json:"licenseListVersion,omitempty"`
	Licenses           []SpdxLicense `json:"licenses"`
	ReleaseDate        string        `json:"releaseDate,omitempty"`
}

var SpdxLicenses map[string]SpdxLicense

func init() {
	SpdxLicenses = make(map[string]SpdxLicense)

	licensesData, err := licensesFile.ReadFile("licenses.json")
	if err != nil {
		panic(err)
	}

	var spdxLicensesContent spdxLicensesJson
	err = json.Unmarshal(licensesData, &spdxLicensesContent)
	if err != nil {
		panic(err)
	}

	for _, license := range spdxLicensesContent.Licenses {
		if license.LicenseId != "" && license.Reference != "" {
			SpdxLicenses[license.LicenseId] = license
		}
	}
}

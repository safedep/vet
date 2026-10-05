package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestLicenses(t *testing.T) {
	id := func(s string) cdx.LicenseChoice { return cdx.LicenseChoice{License: &cdx.License{ID: s}} }
	name := func(s string) cdx.LicenseChoice { return cdx.LicenseChoice{License: &cdx.License{Name: s}} }
	cases := []struct {
		name     string
		declared []string
		want     cdx.Licenses
	}{
		{"spdx ids", []string{"MIT", "apache-2.0"}, cdx.Licenses{id("MIT"), id("Apache-2.0")}},
		{"one expression", []string{"Apache-2.0 OR MIT"}, cdx.Licenses{{Expression: "Apache-2.0 OR MIT"}}},
		{"id and expression", []string{"BSD-3-Clause", "Apache-2.0 OR MIT"}, cdx.Licenses{{Expression: "BSD-3-Clause AND (Apache-2.0 OR MIT)"}}},
		{"unknown name", []string{"Proprietary"}, cdx.Licenses{name("Proprietary")}},
		{"expression and unknown name", []string{"Apache-2.0 OR MIT", "Custom"}, cdx.Licenses{name("Apache-2.0 OR MIT"), name("Custom")}},
		{"deprecated id", []string{"GPL-3.0"}, cdx.Licenses{{Expression: "GPL-3.0-only"}}},
		{"blank value", []string{" "}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, licenses(tc.declared))
		})
	}
}

func TestAdvisorySource(t *testing.T) {
	cases := map[string]cdx.Source{
		"CVE-2023-49092":      {Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-49092"},
		"GHSA-c38w-74pg-36hr": {Name: "GitHub", URL: "https://github.com/advisories/GHSA-c38w-74pg-36hr"},
		"RUSTSEC-2023-0071":   {Name: "OSV", URL: "https://osv.dev/vulnerability/RUSTSEC-2023-0071"},
	}
	for id, want := range cases {
		assert.Equal(t, &want, advisorySource(id), id)
	}
}

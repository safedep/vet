package gitlab

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/finding"
)

func TestIdentifiers(t *testing.T) {
	many := make([]string, 0, 30)
	for i := range 30 {
		many = append(many, fmt.Sprintf("CVE-2026-%05d", i))
	}
	cases := []struct {
		name string
		f    finding.Finding
		want []string
	}{
		{"control only", finding.Finding{ControlID: "malware", Title: "Malicious package"}, []string{"malware"}},
		{
			"advisories from the title and the evidence",
			finding.Finding{
				ControlID: "vulnerability", Title: "GHSA-29mw-wpgm-hmr9 in npm/lodash@4.17.20: Prototype pollution",
				Evidence: []finding.Evidence{{Summary: "GHSA-29mw-wpgm-hmr9 (aliases [CVE-2020-28500 CWE-400])"}},
			},
			[]string{"vulnerability", "CVE-2020-28500", "GHSA-29mw-wpgm-hmr9", "CWE-400"},
		},
		{"at most 20", finding.Finding{ControlID: "vulnerability", Title: strings.Join(many, " ")}, append([]string{"vulnerability"}, many[:19]...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := identifiers(&tc.f)
			names := make([]string, 0, len(got))
			for _, id := range got {
				names = append(names, id.Name)
			}
			assert.Equal(t, tc.want, names)
		})
	}
}

func TestIdentifierURLs(t *testing.T) {
	got := identifiers(&finding.Finding{ControlID: "vulnerability", Title: "CVE-2020-28500 CWE-400 GHSA-29mw-wpgm-hmr9"})
	urls := map[string]string{}
	for _, id := range got[1:] {
		urls[id.Type] = id.URL
	}
	assert.Equal(t, map[string]string{
		"cve":  "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
		"ghsa": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
		"cwe":  "https://cwe.mitre.org/data/definitions/400.html",
	}, urls)
}

func TestSeverity(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SeverityCritical: "Critical", finding.SeverityHigh: "High", finding.SeverityMedium: "Medium",
		finding.SeverityLow: "Low", finding.SeverityInfo: "Info", "bogus": "Unknown",
	}
	for in, want := range cases {
		assert.Equal(t, want, severity(in), in)
	}
}

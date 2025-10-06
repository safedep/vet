package common

import (
	"fmt"
	"strings"
)

func GetCveReferenceURL(cve string) string {
	return fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cve)
}

func GetCweReferenceURL(cwe string) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cwe, "CWE-")) // CWE Require only the number, ie. CWE-123 -> 123
}

func GetGhsaReferenceURL(ghsa string) string {
	return fmt.Sprintf("https://github.com/advisories/%s", ghsa)
}

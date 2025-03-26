package common

import (
	"fmt"
	"strings"
)

// GetIdentifierURL returns the URL for a given identifier and value
// Some Values need to be trimmed to use it in the URL
func GetIdentifierURL(identifier, value string) string {
	switch identifier {
	case "cve":
		return fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", value)
	case "cwe":
		return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(value, "CWE-")) // CWE Rquire only the number, ie. CWE-123 -> 123
	case "ghsa":
		return fmt.Sprintf("https://github.com/advisories/%s", value)
	}
	return ""
}

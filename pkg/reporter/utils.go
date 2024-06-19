package reporter

import (
	"fmt"
	"strings"
)

func vulnIdToLink(vulnID string) string {
	vid := strings.ToLower(vulnID)

	if strings.HasPrefix(vid, "ghsa-") {
		return fmt.Sprintf("https://github.com/advisories/%s", vulnID)
	} else if strings.HasPrefix(vid, "cve-") {
		return fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", vulnID)
	} else {
		return "#"
	}
}

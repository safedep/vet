package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVulnIdToLink(t *testing.T) {
	tests := []struct {
		name     string
		vulnID   string
		expected string
	}{
		{
			name:     "GHSA",
			vulnID:   "GHSA-abc",
			expected: "https://github.com/advisories/GHSA-abc",
		},
		{
			name:     "CVE",
			vulnID:   "CVE-2021-1234",
			expected: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1234",
		},
		{
			name:     "Unknown",
			vulnID:   "unknown",
			expected: "#",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := vulnIdToLink(test.vulnID)
			assert.Equal(t, test.expected, actual)
		})
	}
}

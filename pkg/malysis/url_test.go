package malysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReportURL(t *testing.T) {
	reportId := "test-report-123"
	expected := "https://platform.safedep.io/community/malysis/test-report-123"
	actual := ReportURL(reportId)
	assert.Equal(t, expected, actual)
}

func TestReportURLWithCustomBase(t *testing.T) {
	tests := []struct {
		name     string
		reportId string
		baseURL  string
		expected string
	}{
		{
			name:     "custom base URL",
			reportId: "test-report-123",
			baseURL:  "https://blog.example.com/malware-reports",
			expected: "https://blog.example.com/malware-reports/test-report-123",
		},
		{
			name:     "empty base URL should fallback to default",
			reportId: "test-report-456",
			baseURL:  "",
			expected: "https://platform.safedep.io/community/malysis/test-report-456",
		},
		{
			name:     "base URL with trailing slash",
			reportId: "test-report-789",
			baseURL:  "https://security.company.com/reports/",
			expected: "https://security.company.com/reports//test-report-789",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := ReportURLWithCustomBase(tc.reportId, tc.baseURL)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
package malysis

import "fmt"

func ReportURL(reportId string) string {
	return fmt.Sprintf("https://platform.safedep.io/community/malysis/%s", reportId)
}

func ReportURLWithCustomBase(reportId string, baseURL string) string {
	if baseURL == "" {
		return ReportURL(reportId)
	}
	return fmt.Sprintf("%s/%s", baseURL, reportId)
}

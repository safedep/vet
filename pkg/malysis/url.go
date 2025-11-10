package malysis

import "fmt"

func ReportURL(reportId string) string {
	return fmt.Sprintf("https://app.safedep.io/community/malysis/%s", reportId)
}

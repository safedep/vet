package malysis

import "fmt"

func ReportURL(reportId string) string {
	return fmt.Sprintf("https://platform.safedep.io/community/malysis/%s", reportId)
}

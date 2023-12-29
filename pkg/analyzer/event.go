package analyzer

import (
	"fmt"

	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	"github.com/safedep/vet/pkg/models"
)

func (ev *AnalyzerEvent) IsFailOnError() bool {
	return ev.Type == ET_AnalyzerFailOnError
}

func (ev *AnalyzerEvent) IsFilterMatch() bool {
	return ev.Type == ET_FilterExpressionMatched
}

func (ev *AnalyzerEvent) IsLockfilePoisoningSignal() bool {
	return ev.Type == ET_LockfilePoisoningSignal
}

func ThreatInstanceId(id jsonreportspec.ReportThreat_ReportThreatId,
	st jsonreportspec.ReportThreat_SubjectType,
	s string) string {
	return models.IdGen(fmt.Sprintf("%s-%s-%s", id.String(), st.String(), s))
}

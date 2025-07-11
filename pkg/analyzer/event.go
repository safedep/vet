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

// ThreatInstanceID generates a unique identifier for a threat instance
func ThreatInstanceID(id jsonreportspec.ReportThreat_ReportThreatId,
	st jsonreportspec.ReportThreat_SubjectType,
	s string,
) string {
	return models.IDGen(fmt.Sprintf("%s-%s-%s", id.String(), st.String(), s))
}

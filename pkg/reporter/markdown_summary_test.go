package reporter

import (
	"strings"
	"testing"

	"github.com/safedep/dry/reporting/markdown"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
)

func TestGroupLockfilePoisoningThreatsByURL(t *testing.T) {
	threats := []*jsonreportspec.ReportThreat{
		{
			Id:          jsonreportspec.ReportThreat_LockfilePoisoning,
			SubjectType: jsonreportspec.ReportThreat_Manifest,
			Subject:     "package-lock.json",
			Message:     "Package `left-pad` resolved to an untrusted host `https://repo.example.com/private/left-pad.tgz`",
		},
		{
			Id:          jsonreportspec.ReportThreat_LockfilePoisoning,
			SubjectType: jsonreportspec.ReportThreat_Manifest,
			Subject:     "other-package-lock.json",
			Message:     "Package `lodash` resolved to an untrusted host `https://repo.example.com/private/left-pad.tgz`",
		},
	}

	grouped := groupLockfilePoisoningThreatsByURL(threats)
	require.Len(t, grouped, 1)

	assert.Equal(t, 2, grouped[0].count)
	assert.Equal(t, "https://repo.example.com/private/left-pad.tgz", grouped[0].url)
	assert.Equal(t, "package-lock.json", grouped[0].subject)
}

func TestAddThreatsSectionConsolidatesLockfilePoisoningByURL(t *testing.T) {
	r := &markdownSummaryReporter{}

	internalModel := &vetResultInternalModel{
		threats: map[jsonreportspec.ReportThreat_ReportThreatId][]*jsonreportspec.ReportThreat{
			jsonreportspec.ReportThreat_LockfilePoisoning: {
				{
					Id:          jsonreportspec.ReportThreat_LockfilePoisoning,
					SubjectType: jsonreportspec.ReportThreat_Manifest,
					Subject:     "package-lock.json",
					Message:     "Package `left-pad` resolved to an untrusted host `https://repo.example.com/private/left-pad.tgz`",
				},
				{
					Id:          jsonreportspec.ReportThreat_LockfilePoisoning,
					SubjectType: jsonreportspec.ReportThreat_Manifest,
					Subject:     "package-lock.json",
					Message:     "Package `lodash` resolved to an untrusted host `https://repo.example.com/private/left-pad.tgz`",
				},
			},
		},
	}

	builder := markdown.NewMarkdownBuilder()
	err := r.addThreatsSection(builder, internalModel)
	require.NoError(t, err)

	output := builder.Build()
	assert.Contains(t, output, "2 lockfile poisoning signals share URL `https://repo.example.com/private/left-pad.tgz`")
	assert.Equal(t, 1, strings.Count(output, "share URL"))
	assert.NotContains(t, output, "Package `left-pad`")
	assert.NotContains(t, output, "Package `lodash`")
}

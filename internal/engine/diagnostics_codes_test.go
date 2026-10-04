package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/plugin/plugintest"
)

// TestSampleReportUsesEngineCodes keeps the sample report of the sink and
// view tests on the diagnostic codes that the engine records.
func TestSampleReportUsesEngineCodes(t *testing.T) {
	codes := map[string]bool{
		CodeExtractFailed: true, CodeUnknownEcosystem: true, CodeEnrichUnavailable: true, CodeEnrichFailed: true,
		CodeControlUnavailable: true, CodeControlFailed: true, CodeInvalidFinding: true,
	}
	for rec, err := range plugintest.SampleReport().Records(context.Background()) {
		require.NoError(t, err)
		if d := rec.Diagnostic; d != nil {
			assert.True(t, codes[d.Code], d.Code)
		}
	}
}

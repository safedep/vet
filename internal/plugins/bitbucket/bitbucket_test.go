package bitbucket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"a longer title", 5, "a lo…"},
		{"ünïcödé", 4, "ünï…"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, render.Truncate(tc.in, tc.n), tc.in)
	}
}

func TestAnnotationSeverity(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SeverityCritical: "CRITICAL", finding.SeverityHigh: "HIGH", finding.SeverityMedium: "MEDIUM",
		finding.SeverityLow: "LOW", finding.SeverityInfo: "LOW",
	}
	for in, want := range cases {
		assert.Equal(t, want, annotationSeverity(in), in)
	}
}

func write(t *testing.T, s *plugintest.MemState) file {
	t.Helper()
	sink, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, sink.Write(context.Background(), s, &buf))
	var out file
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	return out
}

func TestResultFollowsTheGate(t *testing.T) {
	cases := map[report.GateOutcome]string{report.GateNone: "", report.GatePass: "PASSED", report.GateFail: "FAILED"}
	for outcome, want := range cases {
		s := plugintest.SampleReport()
		tr := *s.Trailer()
		tr.Gate.Outcome = outcome
		s.TrailerValue = &tr
		assert.Equal(t, want, write(t, s).Report.Result, outcome)
	}
}

func TestAnnotationLimit(t *testing.T) {
	s := plugintest.SampleReport()
	base := *s.FindingList[0]
	s.FindingList = nil
	for i := range maxAnnotations + 5 {
		f := base
		f.ID = fmt.Sprintf("f-%04d", i)
		f.Suppression = nil
		f.Severity = finding.SeverityLow
		if i == maxAnnotations+4 {
			f.Severity = finding.SeverityCritical
		}
		s.FindingList = append(s.FindingList, &f)
	}
	out := write(t, s)
	require.Len(t, out.Annotations, maxAnnotations)
	assert.Equal(t, "CRITICAL", out.Annotations[0].Severity, "the most severe findings stay")
	assert.True(t, strings.HasPrefix(out.Annotations[1].ExternalID, "f-"))
}

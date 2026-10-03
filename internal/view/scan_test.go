package view

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func capture(t *testing.T, mode output.Mode, fn func()) string {
	t.Helper()
	var stderr bytes.Buffer
	prevMode := output.CurrentMode()
	output.SetMode(mode)
	output.SetWriters(io.Discard, &stderr)
	t.Cleanup(func() {
		output.SetMode(prevMode)
		output.SetWriters(os.Stdout, os.Stderr)
	})
	fn()
	return stderr.String()
}

func run(v *Scan) {
	v.Stage(engine.StageExtract, 1, 4)
	v.Progress(engine.StageExtract, 3, 0)
	v.Stage(engine.StageEnrich, 2, 4)
	v.Progress(engine.StageEnrich, 2, 0)
	v.Progress(engine.StageEnrich, 5, 0)
	v.Stage(engine.StageEvaluate, 3, 4)
	v.Progress(engine.StageEvaluate, 1, 1)
	v.Stage(engine.StageReport, 4, 4)
}

func TestScanGolden(t *testing.T) {
	sample := plugintest.SampleReport()
	diags := sample.DiagnosticList
	fail := *sample.Trailer()
	fail.Gate = report.Gate{Outcome: report.GateFail, FailOn: finding.SeverityHigh, Rules: []string{"no-malware"}, FindingIDs: []string{"f-478cf580259c82ac"}}
	pass := *sample.Trailer()
	pass.Gate = report.Gate{Outcome: report.GatePass, FailOn: finding.SeverityCritical}
	delta := *sample.Header()
	delta.Scan.Mode, delta.Scan.BaseRef = report.ScanModeDelta, "origin/main"

	cases := []struct {
		name    string
		opts    Options
		header  *report.Header
		trailer *report.Trailer
	}{
		{name: "no-gate", opts: Options{Target: "."}, header: sample.Header(), trailer: sample.Trailer()},
		{name: "gate-fail", opts: Options{Target: "my app"}, header: sample.Header(), trailer: &fail},
		{name: "gate-pass", opts: Options{Target: "."}, header: sample.Header(), trailer: &pass},
		{name: "pull-request", opts: Options{Target: ".", BaseRef: "origin/main"}, header: &delta, trailer: sample.Trailer()},
	}
	modes := map[string]output.Mode{"rich": output.Rich, "plain": output.Plain, "agent": output.Agent}
	for _, tc := range cases {
		for mname, mode := range modes {
			t.Run(tc.name+"/"+mname, func(t *testing.T) {
				got := capture(t, mode, func() {
					v := NewScan(tc.opts)
					run(v)
					v.Finish(tc.header, tc.trailer, diags, Changes{Packages: 4, Workflows: 1, Unchanged: 210})
				})
				golden.Assert(t, filepath.Join("testdata", tc.name+"-"+mname+".golden"), []byte(got))
			})
		}
	}
}

func TestQuietKeepsTheFailure(t *testing.T) {
	sample := plugintest.SampleReport()
	fail := *sample.Trailer()
	fail.Gate = report.Gate{Outcome: report.GateFail, FailOn: finding.SeverityHigh, FindingIDs: []string{"f-1"}}
	output.SetVerbosity(output.Silent)
	t.Cleanup(func() { output.SetVerbosity(output.Normal) })
	got := capture(t, output.Plain, func() {
		v := NewScan(Options{Target: "."})
		run(v)
		v.Finish(sample.Header(), &fail, nil, Changes{})
	})
	assert.Equal(t, "[ERR] Gate failed: 1 finding at high or above\n", got)
}

func TestCountChanges(t *testing.T) {
	s := plugintest.SampleReport()
	s.ManifestList[0].Packages[0].Change = model.ChangeAdded
	s.ManifestList = append(s.ManifestList, &model.Manifest{ID: "w", Path: ".github/workflows/ci.yml", Kind: model.ManifestKindWorkflow, Change: model.ChangeModified})
	c, err := CountChanges(context.Background(), s)
	require.NoError(t, err)
	assert.Equal(t, Changes{Packages: 1, Workflows: 1, Unchanged: 1}, c)
}

func TestDiagnosticsShowsAFewToAHuman(t *testing.T) {
	sample := plugintest.SampleReport()
	var diags []*report.Diagnostic
	for i := range 8 {
		diags = append(diags, &report.Diagnostic{Level: report.DiagnosticWarning, Code: "extract_failed", Component: "extract", Message: fmt.Sprintf("file %d", i)})
	}
	diags = append(diags, &report.Diagnostic{Level: report.DiagnosticError, Code: "enrich_failed", Component: "malysis", Message: "unavailable"})
	cases := []struct {
		name      string
		mode      output.Mode
		verbosity output.Verbosity
		lines     int
	}{
		{"plain", output.Plain, output.Normal, shownDiagnostics + 1},
		{"plain -v", output.Plain, output.Verbose, len(diags)},
		{"agent", output.Agent, output.Normal, len(diags)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetVerbosity(tc.verbosity)
			t.Cleanup(func() { output.SetVerbosity(output.Normal) })
			got := capture(t, tc.mode, func() {
				v := NewScan(Options{Saved: true})
				v.diagnostics(sample.Header(), diags)
			})
			lines := strings.Split(strings.TrimSpace(got), "\n")
			assert.Len(t, lines, tc.lines)
			if tc.lines < len(diags) {
				assert.Contains(t, lines[0], "malysis", "an error comes first")
				assert.Contains(t, lines[len(lines)-1], "4 more diagnostics. Show all: vet report show "+sample.Header().Scan.ID+" -v")
			}
		})
	}
}

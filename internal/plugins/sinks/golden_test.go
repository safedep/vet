package sinks_test

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

// pullRequest is the sample report in pull request mode, with Insights data
// and a failed gate.
func pullRequest() *plugintest.MemState {
	s := plugintest.SampleReport()
	h := *s.Header()
	h.Scan.Mode, h.Scan.BaseRef = report.ScanModeDelta, "origin/main"
	s.HeaderValue = &h
	published := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pad := s.ManifestList[0].Packages[1]
	pad.Change = model.ChangeUpgraded
	pad.PreviousVersion = "1.2.0"
	pad.Insight = &model.Insight{
		Licenses: []string{"WTFPL"}, PublishedAt: &published,
		Vulnerabilities: []model.Vulnerability{{ID: "GHSA-stub-0001", Aliases: []string{"CVE-2026-0001"}, Summary: "Prototype pollution", Severity: "high", CVSS: 7.5}},
	}
	evil := s.ManifestList[0].Packages[0]
	evil.Change = model.ChangeAdded
	evil.Malware = &model.MalwareAnalysis{Malicious: true, Verified: true}
	for _, f := range s.FindingList {
		f.Change = model.ChangeAdded
	}
	tr := *s.Trailer()
	tr.Gate = report.Gate{Outcome: report.GateFail, FailOn: report.FailOn(finding.SeverityHigh), FindingIDs: []string{s.FindingList[0].ID}}
	s.TrailerValue = &tr
	return s
}

// clean is a report with packages and no findings.
func clean() *plugintest.MemState {
	s := plugintest.SampleReport()
	s.FindingList, s.InventoryList, s.DiagnosticList = nil, nil, nil
	return s
}

func TestSinksGolden(t *testing.T) {
	output.SetWidthOverride(120)
	t.Cleanup(func() { output.SetWidthOverride(0) })
	reports := map[string]func() *plugintest.MemState{"sample": plugintest.SampleReport, "pull-request": pullRequest, "clean": clean}
	modes := map[string]output.Mode{"rich": output.Rich, "plain": output.Plain}

	for _, spec := range sinks.Builtin() {
		for name, build := range reports {
			for modeName, mode := range modes {
				if spec.Name != "table" && modeName == "plain" {
					continue
				}
				file := name
				if spec.Name == "table" {
					file = name + "-" + modeName
				}
				t.Run(spec.Name+"/"+file, func(t *testing.T) {
					prev := output.CurrentMode()
					output.SetMode(mode)
					t.Cleanup(func() { output.SetMode(prev) })
					s, err := spec.New(plugin.MapConfig(nil))
					require.NoError(t, err)
					if c, ok := s.(plugin.Checker); ok && c.Check() != nil {
						t.Skip("a stub sink writes nothing")
					}
					got := plugintest.TestSink(t, s, build())
					golden.Assert(t, filepath.Join("testdata", spec.Name, file+".golden"), got)
				})
			}
		}
	}
}

func TestJSONFormatsReadBack(t *testing.T) {
	for _, format := range []string{"json", "jsonl"} {
		t.Run(format, func(t *testing.T) {
			s, err := sinks.Builtin().New(format, nil)
			require.NoError(t, err)
			r := pullRequest()
			doc, err := report.Read(bytes.NewReader(plugintest.TestSink(t, s, r)))
			require.NoError(t, err)
			assert.Equal(t, *r.Header(), doc.Header)
			assert.Equal(t, r.Trailer().RecordCount, uint64(len(doc.Records)))
			assert.Equal(t, report.GateFail, doc.Trailer.Gate.Outcome)
		})
	}
}

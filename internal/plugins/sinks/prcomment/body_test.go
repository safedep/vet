package prcomment

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

var testLinks = links{
	Server: "https://github.com", Repository: "acme/app",
	Head: "2222222222222222222222222222222222222222", Run: "https://github.com/acme/app/actions/runs/99",
}

// pullRequest is the sample report in pull request mode with a failed
// attacks gate.
func pullRequest(gate report.GateOutcome) *plugintest.MemState {
	s := plugintest.SampleReport()
	h := *s.Header()
	h.Scan.Mode, h.Scan.BaseRef = report.ScanModeDelta, "origin/main"
	h.Tool.Version = "2.0.0-alpha.20261005063951"
	s.HeaderValue = &h
	for _, p := range s.ManifestList[0].Packages {
		p.Change = model.ChangeAdded
	}
	for _, f := range s.FindingList {
		f.Change = model.ChangeAdded
	}
	s.FindingList[0].Remediation.Command = "npm uninstall evil-colors"
	tr := *s.Trailer()
	tr.Gate = report.Gate{Outcome: gate}
	if gate == report.GateFail {
		tr.Gate.FailOn = report.FailOnAttacks
		tr.Gate.FindingIDs = []string{s.FindingList[0].ID}
	}
	s.TrailerValue = &tr
	return s
}

func newInput(t *testing.T, r plugin.Report) *input {
	t.Helper()
	sink, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	c, err := sink.(*Sink).input(context.Background(), r)
	require.NoError(t, err)
	c.links = testLinks
	return c
}

func TestBodyGolden(t *testing.T) {
	cases := map[string]func(t *testing.T) *input{
		"blocked": func(t *testing.T) *input { return newInput(t, pullRequest(report.GateFail)) },
		"after-fix": func(t *testing.T) *input {
			s := pullRequest(report.GatePass)
			fixed := s.FindingList[0].ID
			s.FindingList = s.FindingList[1:]
			s.DiagnosticList = nil
			c := newInput(t, s)
			c.old = &state{Version: stateVersion, Findings: []string{fixed, s.FindingList[0].ID}}
			return c
		},
		"observe": func(t *testing.T) *input { return newInput(t, pullRequest(report.GateNone)) },
		"clean-receipt": func(t *testing.T) *input {
			s := pullRequest(report.GatePass)
			s.FindingList, s.DiagnosticList = nil, nil
			return newInput(t, s)
		},
		"fork": func(t *testing.T) *input {
			c := newInput(t, pullRequest(report.GateFail))
			c.via = "Posted by the SafeDep comment proxy, because the workflow token of a fork cannot write comments."
			return c
		},
		"policy-edited": func(t *testing.T) *input {
			s := pullRequest(report.GateFail)
			s.TrailerValue.Gate.Policy = "origin/main:.github/vet/policy.yml"
			s.TrailerValue.Gate.PolicyChanged = true
			return newInput(t, s)
		},
		"plain-dialect": func(t *testing.T) *input {
			c := newInput(t, pullRequest(report.GateFail))
			c.dialect = dialect{}
			return c
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			golden.Assert(t, filepath.Join("testdata", name+".md"), []byte(build(t).body()))
		})
	}
}

func TestBodyCutsToSize(t *testing.T) {
	s := pullRequest(report.GateFail)
	pad := s.ManifestList[0].Packages[1]
	long := strings.Repeat("A long advisory text. ", 45)
	var failed []string
	for i := range 450 {
		sev := finding.SeverityHigh
		if i%3 == 0 {
			sev = finding.SeverityMedium
		}
		f := finding.ForPackage(finding.Meta{
			ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev,
			Title: fmt.Sprintf("GHSA-%04d", i), Description: long,
		}, "package-lock.json", pad, finding.Key{Discriminator: fmt.Sprintf("GHSA-%04d", i)})
		s.FindingList = append(s.FindingList, &f)
		if i%2 == 0 {
			failed = append(failed, f.ID)
		}
	}
	s.TrailerValue.Gate.FindingIDs = append(s.TrailerValue.Gate.FindingIDs, failed...)

	body := newInput(t, s).body()
	assert.LessOrEqual(t, utf8.RuneCountInString(body), maxChars)
	assert.Contains(t, body, "more in the full report")
	assert.NotContains(t, body, stateOpen, "the state goes before the cards")
	assert.True(t, strings.HasPrefix(body, markerOf("")), "the marker stays")
}

func TestUntrustedTextIsBounded(t *testing.T) {
	s := pullRequest(report.GateFail)
	huge := strings.Repeat("x", 100000)
	s.FindingList[0].Title = huge
	s.FindingList[0].Description = huge
	s.FindingList[0].Subject.Package.RawName = huge
	body := newInput(t, s).body()
	assert.Less(t, utf8.RuneCountInString(body), 20000, "a single finding cannot fill the comment")
}

func TestKeyedMarker(t *testing.T) {
	assert.Equal(t, "<!-- vet:pr-comment v1 -->", markerOf(""))
	assert.Equal(t, "<!-- vet:pr-comment v1 api -->", markerOf("api"))
	_, err := New(plugin.MapConfig{"key": "a b"})
	assert.ErrorContains(t, err, "key must hold only")
}

func TestRef(t *testing.T) {
	cases := map[string]string{
		"2.0.0":                              "v2.0.0",
		"v2.1.3":                             "v2.1.3",
		"2.0.0-alpha.20261005063951":         "v2.0.0-alpha.20261005063951",
		"devel":                              devRef,
		"v2.0.0-20261005063951-abcdefabcdef": devRef,
		"2.0.0+dirty":                        devRef,
	}
	for version, want := range cases {
		c := &input{header: &report.Header{Tool: report.Tool{Version: version}}}
		assert.Equal(t, want, c.ref(), version)
	}
}

func TestWrite(t *testing.T) {
	sink, err := New(plugin.MapConfig{"create": "findings"})
	require.NoError(t, err)
	sink.(*Sink).getenv = func(string) string { return "" }
	var b bytes.Buffer
	require.NoError(t, sink.Write(context.Background(), pullRequest(report.GateFail), &b))
	assert.True(t, strings.HasPrefix(b.String(), markerOf("")))
	assert.Contains(t, b.String(), "`package-lock.json:42`", "no CI, so no file link")

	_, err = New(plugin.MapConfig{"create": "always"})
	assert.ErrorContains(t, err, "create must be changes or findings")
}

func TestTargetPrefix(t *testing.T) {
	ws := t.TempDir()
	cases := []struct {
		target, prefix string
		noFiles        bool
	}{
		{target: ws},
		{target: filepath.Join(ws, "svc", "api"), prefix: "svc/api/"},
		{target: t.TempDir(), noFiles: true},
	}
	for _, tc := range cases {
		prefix, noFiles := targetPrefix(ws, tc.target)
		assert.Equal(t, tc.prefix, prefix, tc.target)
		assert.Equal(t, tc.noFiles, noFiles, tc.target)
	}
	_, noFiles := targetPrefix("", ws)
	assert.True(t, noFiles, "no workspace, no file links")
}

func TestProgressKeepsTheBaselineOnARerun(t *testing.T) {
	s := pullRequest(report.GatePass)
	s.DiagnosticList = nil
	open := s.FindingList[1].ID
	c := newInput(t, s)
	gone := "f-0000000000000001"
	c.old = &state{Version: stateVersion, HeadSHA: testLinks.Head, Findings: []string{open}, Since: []string{gone, open}}
	body := c.body()
	assert.Contains(t, body, "**Since the last push:** 1 resolved", "a re-run of the same head compares with the push before it")
	st, ok := decodeState(body)
	require.True(t, ok)
	assert.Equal(t, []string{gone, open}, st.Since)
}

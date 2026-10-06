package view

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// stepClock advances 1.5 seconds on each call, so each stage takes 1.5s.
func stepClock() func() time.Time {
	t := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(1500 * time.Millisecond)
		return t
	}
}

func newScan(o Options) *Scan {
	v := NewScan(o)
	v.now = stepClock()
	return v
}

func run(v *Scan) {
	v.Stage(engine.StageExtract, 1, 4)
	v.Progress(engine.StageExtract, 3, 0)
	v.Stage(engine.StageEnrich, 2, 4)
	v.Progress(engine.StageEnrich, 2, 5)
	v.Progress(engine.StageEnrich, 5, 5)
	v.Stage(engine.StageEvaluate, 3, 4)
	v.Progress(engine.StageEvaluate, 1, 1)
	v.Stage(engine.StageReport, 4, 4)
	v.Report(nil)
}

// vulnerability is a high finding on left-pad with a fixed version.
func vulnerability() *finding.Finding {
	pad := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0")}
	f := finding.ForPackage(finding.Meta{
		ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "GHSA-1",
	}, "package-lock.json", pad, finding.Key{Discriminator: "GHSA-1"})
	f.Remediation = &finding.Remediation{Summary: "Upgrade left-pad.", FixedVersion: "1.3.1"}
	return &f
}

func TestScanGolden(t *testing.T) {
	sample := plugintest.SampleReport()
	vuln := vulnerability()
	sample.FindingList = append(sample.FindingList, vuln)
	summary, err := Summarize(context.Background(), sample)
	require.NoError(t, err)
	summary.Changes = Changes{Packages: 4, Workflows: 1, Unchanged: 210}

	fail := *sample.Trailer()
	fail.Gate = report.Gate{Outcome: report.GateFail, FailOn: report.FailOn(finding.SeverityHigh), Rules: []string{"no-malware"}, FindingIDs: []string{"f-478cf580259c82ac", vuln.ID}}
	failOn := *sample.Trailer()
	failOn.Gate = report.Gate{Outcome: report.GateFail, FailOn: report.FailOn(finding.SeverityHigh), FindingIDs: []string{"f-478cf580259c82ac", vuln.ID}}
	pass := *sample.Trailer()
	pass.Gate = report.Gate{Outcome: report.GatePass, FailOn: report.FailOn(finding.SeverityCritical)}
	delta := *sample.Header()
	delta.Scan.Mode, delta.Scan.BaseRef = report.ScanModeDelta, "origin/main"
	empty := *sample.Trailer()
	empty.Summary = report.Summary{}
	machine := *sample.Header()
	machine.Scan.Kind = report.ScanKindEndpoint

	cases := []struct {
		name    string
		opts    Options
		header  *report.Header
		trailer *report.Trailer
		summary Summary
	}{
		{name: "no-gate", opts: Options{Target: "."}, header: sample.Header(), trailer: sample.Trailer(), summary: summary},
		{name: "gate-fail", opts: Options{Target: "my app"}, header: sample.Header(), trailer: &fail, summary: summary},
		{name: "gate-fail-on", opts: Options{Target: "."}, header: sample.Header(), trailer: &failOn, summary: summary},
		{name: "gate-pass", opts: Options{Target: "."}, header: sample.Header(), trailer: &pass, summary: summary},
		{name: "pull-request", opts: Options{Target: ".", BaseRef: "origin/main"}, header: &delta, trailer: sample.Trailer(), summary: summary},
		{name: "saved", opts: Options{Saved: true}, header: sample.Header(), trailer: &failOn, summary: summary},
		{name: "no-manifest", opts: Options{Target: "."}, header: sample.Header(), trailer: &empty},
		{name: "endpoint", opts: Options{Kind: report.ScanKindEndpoint}, header: &machine, trailer: &empty},
	}
	modes := map[string]output.Mode{"rich": output.Rich, "plain": output.Plain, "agent": output.Agent}
	for _, tc := range cases {
		for mname, mode := range modes {
			t.Run(tc.name+"/"+mname, func(t *testing.T) {
				got := capture(t, mode, func() {
					v := newScan(tc.opts)
					if !tc.opts.Saved {
						run(v)
					}
					v.Finish(tc.header, tc.trailer, tc.summary)
				})
				golden.Assert(t, filepath.Join("testdata", tc.name+"-"+mname+".golden"), []byte(got))
			})
		}
	}
}

func TestQuietKeepsTheFailure(t *testing.T) {
	sample := plugintest.SampleReport()
	fail := *sample.Trailer()
	fail.Gate = report.Gate{Outcome: report.GateFail, FailOn: report.FailOn(finding.SeverityHigh), FindingIDs: []string{"f-1"}}
	output.SetVerbosity(output.Silent)
	t.Cleanup(func() { output.SetVerbosity(output.Normal) })
	got := capture(t, output.Plain, func() {
		v := newScan(Options{Target: "."})
		run(v)
		v.Finish(sample.Header(), &fail, Summary{})
	})
	assert.Equal(t, "[ERR] Gate failed: 1 finding at high or above (--fail-on high)\n", got)
}

func TestSummarize(t *testing.T) {
	s := plugintest.SampleReport()
	s.ManifestList[0].Packages[0].Change = model.ChangeAdded
	s.ManifestList[0].Packages[1].Insight = &model.Insight{LatestVersion: "1.3.1"}
	s.ManifestList = append(s.ManifestList, &model.Manifest{ID: "w", Path: ".github/workflows/ci.yml", Kind: model.ManifestKindWorkflow, Change: model.ChangeModified})
	s.FindingList = append(s.FindingList, vulnerability())
	got, err := Summarize(context.Background(), s)
	require.NoError(t, err)
	assert.Equal(t, Changes{Packages: 1, Workflows: 1, Unchanged: 1}, got.Changes)
	assert.Len(t, got.Diagnostics, 1)
	assert.Equal(t, map[model.PackageKey]string{model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0").Key(): "1.3.1"}, got.Latest)
	var severities []finding.Severity
	for _, f := range got.Findings {
		severities = append(severities, f.Severity)
	}
	assert.Equal(t, []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium}, severities,
		"the most severe first, and no suppressed finding")
}

func TestDiagnosticsGroupsForAHuman(t *testing.T) {
	sample := plugintest.SampleReport()
	id := sample.Header().Scan.ID
	var extract []*report.Diagnostic
	for i := range 7 {
		extract = append(extract, &report.Diagnostic{Level: report.DiagnosticWarning, Code: "extract_failed", Component: "extract", Message: fmt.Sprintf("file %d: bad\nline", i), Count: 1})
	}
	failed := &report.Diagnostic{Level: report.DiagnosticError, Code: "enrich_failed", Component: "malysis", Message: "unavailable", Count: 1}
	var components []*report.Diagnostic
	for i := range 7 {
		components = append(components, &report.Diagnostic{Level: report.DiagnosticWarning, Code: "c", Component: fmt.Sprintf("plugin-%d", i), Message: "slow", Count: 1})
	}
	cases := []struct {
		name      string
		diags     []*report.Diagnostic
		mode      output.Mode
		verbosity output.Verbosity
		want      []string
	}{
		{
			name: "one group", diags: append(slices.Clone(extract), failed), mode: output.Plain, verbosity: output.Normal,
			want: []string{
				"[ERR] malysis: unavailable",
				"[WARN] extract: file 0: bad line (and 6 more like it)",
				"Show all: vet report show " + id + " -v",
			},
		},
		{
			name: "more groups than the cap", diags: components, mode: output.Plain, verbosity: output.Normal,
			want: []string{
				"[WARN] plugin-0: slow", "[WARN] plugin-1: slow", "[WARN] plugin-2: slow", "[WARN] plugin-3: slow", "[WARN] plugin-4: slow",
				"2 more diagnostics. Show all: vet report show " + id + " -v",
			},
		},
		{
			name: "no group", diags: []*report.Diagnostic{failed}, mode: output.Plain, verbosity: output.Normal,
			want: []string{"[ERR] malysis: unavailable"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capture(t, tc.mode, func() {
				v := NewScan(Options{Saved: true})
				v.diagnostics(sample.Header(), tc.diags)
			})
			lines := strings.Split(strings.TrimSpace(got), "\n")
			require.Len(t, lines, len(tc.want))
			for i, want := range tc.want {
				assert.Contains(t, lines[i], want)
			}
		})
	}
}

func TestDiagnosticsListsEachWithVerboseOrForAnAgent(t *testing.T) {
	sample := plugintest.SampleReport()
	var diags []*report.Diagnostic
	for i := range 8 {
		diags = append(diags, &report.Diagnostic{Level: report.DiagnosticWarning, Code: "extract_failed", Component: "extract", Message: fmt.Sprintf("file %d", i), Count: 1})
	}
	cases := []struct {
		name      string
		mode      output.Mode
		verbosity output.Verbosity
	}{
		{"plain -v", output.Plain, output.Verbose},
		{"agent", output.Agent, output.Normal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetVerbosity(tc.verbosity)
			t.Cleanup(func() { output.SetVerbosity(output.Normal) })
			got := capture(t, tc.mode, func() {
				v := NewScan(Options{Saved: true})
				v.diagnostics(sample.Header(), diags)
			})
			assert.Len(t, strings.Split(strings.TrimSpace(got), "\n"), len(diags))
			assert.NotContains(t, got, "Show all")
		})
	}
}

func TestCleanMessage(t *testing.T) {
	cases := []struct {
		name, msg, want string
	}{
		{"line break", "bad file\nat line 3", "bad file at line 3"},
		{"escaped line break", `bad file\nat line 3`, "bad file at line 3"},
		{"windows line break", "bad file\r\n  at line 3\n", "bad file at line 3"},
		{"control character", "bad \x1b[31mred", `bad \x1b[31mred`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cleanMessage(tc.msg))
		})
	}
}

func TestFixText(t *testing.T) {
	pkgIn := func(eco model.Ecosystem, name, version, fixed string, sev finding.Severity) *finding.Finding {
		p := &model.Package{ID: model.MustPackageVersion(eco, name, version)}
		f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev, Title: "v"},
			"package-lock.json", p, finding.Key{Discriminator: fixed})
		f.Remediation = &finding.Remediation{Summary: "Upgrade.", FixedVersion: fixed}
		return &f
	}
	pkg := func(name, version, fixed string, sev finding.Severity) *finding.Finding {
		return pkgIn(model.EcosystemNpm, name, version, fixed, sev)
	}
	cases := []struct {
		name     string
		findings []*finding.Finding
		latest   map[model.PackageKey]string
		want     string
	}{
		{name: "no fix", findings: []*finding.Finding{pkg("a", "1.0.0", "", finding.SeverityHigh)}},
		{
			name: "the latest version of a vulnerable package", findings: []*finding.Finding{pkg("a", "1.0.0", "", finding.SeverityHigh)},
			latest: map[model.PackageKey]string{model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0").Key(): "1.2.0"}, want: "upgrade a to 1.2.0",
		},
		{
			name: "two spellings of one PyPI package are one fix with the raw name",
			findings: []*finding.Finding{
				pkgIn(model.EcosystemPyPI, "Django", "2.2.0", "2.2.24", finding.SeverityHigh),
				pkgIn(model.EcosystemPyPI, "django", "2.2", "3.2.4", finding.SeverityHigh),
			},
			want: "upgrade Django to 3.2.4",
		},
		{
			name:     "the PyPI order",
			findings: []*finding.Finding{pkgIn(model.EcosystemPyPI, "pkg", "1.0rc1", "1.0", finding.SeverityHigh)},
			want:     "upgrade pkg to 1.0",
		},
		{
			name:     "no hint with no order",
			findings: []*finding.Finding{pkgIn(model.EcosystemGitHubActions, "actions/checkout", "v3", "v4", finding.SeverityHigh)},
		},
		{name: "a lower version is no upgrade", findings: []*finding.Finding{pkg("a", "1.4.1", "1.3.9", finding.SeverityHigh)}},
		{name: "one package", findings: []*finding.Finding{pkg("minimist", "1.2.0", "1.2.6", finding.SeverityCritical)}, want: "upgrade minimist to 1.2.6"},
		{
			name:     "the highest fix of a package",
			findings: []*finding.Finding{pkg("lodash", "4.17.15", "4.17.19", finding.SeverityHigh), pkg("lodash", "4.17.15", "4.17.21", finding.SeverityHigh), pkg("lodash", "4.17.15", "4.17.16", finding.SeverityMedium)},
			want:     "upgrade lodash to 4.17.21",
		},
		{
			name: "at most three packages",
			findings: []*finding.Finding{
				pkg("a", "1.0.0", "1.0.1", finding.SeverityCritical), pkg("b", "1.0.0", "2.0.0", finding.SeverityHigh),
				pkg("c", "1.0.0", "1.1.0", finding.SeverityHigh), pkg("d", "1.0.0", "1.0.2", finding.SeverityLow),
			},
			want: "upgrade a to 1.0.1, b to 2.0.0 and c to 1.1.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fixText(tc.findings, tc.latest))
		})
	}
}

func TestGateReason(t *testing.T) {
	ids := []string{"f-1", "f-2"}
	cases := []struct {
		name string
		gate report.Gate
		want string
	}{
		{"fail-on", report.Gate{FailOn: report.FailOn(finding.SeverityHigh), FindingIDs: ids}, "2 findings at high or above (--fail-on high)"},
		{"one rule", report.Gate{Rules: []string{"no-malware"}, FindingIDs: ids[:1]}, "1 finding (policy rule no-malware)"},
		{"rules", report.Gate{Rules: []string{"a", "b"}, FindingIDs: ids}, "2 findings (policy rules a and b)"},
		{"both", report.Gate{FailOn: report.FailOn(finding.SeverityHigh), Rules: []string{"a"}, FindingIDs: ids}, "2 findings (--fail-on high, policy rule a)"},
		{"no gate named", report.Gate{FindingIDs: ids}, "2 findings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, gateReason(tc.gate))
		})
	}
}

func TestStepLineGivesTheRunTimeOfASlowStage(t *testing.T) {
	cases := []struct {
		name string
		took time.Duration
		want string
	}{
		{"fast", 300 * time.Millisecond, "› [2/4] Checked 2973 packages\n"},
		{"slow", 2*time.Minute + 51545*time.Millisecond, "› [2/4] Checked 2973 packages in 2m52s\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capture(t, output.Rich, func() {
				v := NewScan(Options{Target: "."})
				start := time.Now()
				v.now = func() time.Time { return start }
				v.Stage(engine.StageEnrich, 2, 4)
				v.Progress(engine.StageEnrich, 2973, 2973)
				v.now = func() time.Time { return start.Add(tc.took) }
				v.Stage(engine.StageEvaluate, 3, 4)
			})
			assert.Equal(t, tc.want, got)
		})
	}
}

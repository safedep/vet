package policy_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// everyPackage reports each package with the severity of its name.
type everyPackage struct{}

func (everyPackage) Controls() []plugin.ControlInfo {
	return []plugin.ControlInfo{{ID: "every", Family: finding.FamilyHygiene, Severity: finding.SeverityInfo, Title: "every"}}
}

func (everyPackage) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range m.Packages {
		sev := finding.SeverityLow
		if p.ID.RawName() == "evil" {
			sev = finding.SeverityCritical
		}
		out = append(out, finding.ForPackage(finding.Meta{ControlID: "every", Family: finding.FamilyHygiene, Severity: sev, Title: p.ID.String()}, m.Path, p, finding.Key{}))
	}
	return out, nil
}

const requirements = "evil==1.0.0\nrequests==2.31.0\nflask==3.0.0\n"

const policyFile = `version: 2
rules:
  - id: no-evil
    when: finding.control_id == "every" && package.name == "evil"
    action: fail
  - id: note-flask
    when: finding.control_id == "every" && package.name == "flask"
    action: warn
suppressions:
  - purl: pkg:pypi/requests
    reason: Reviewed.
  - purl: pkg:pypi/flask
    reason: Old review.
    expires: 2020-01-01
`

func scan(t *testing.T, e *policy.Evaluator) *engine.Result {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(requirements), 0o600))
	store, err := state.Open(ctx, state.Options{StateDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	src, err := sources.New(dir, sources.Options{})
	require.NoError(t, err)
	res, err := engine.Run(ctx, engine.Options{
		Store: store, Source: src, Controls: []engine.Control{{ID: "every", Plugin: everyPackage{}}},
		Extractors:  func(plugin.ArtifactKind) ([]plugin.Extractor, error) { return extractors.Default() },
		OptionsHash: "h", VetVersion: "test", BatchSize: 10,
		Finalize: func(ctx context.Context, s *state.Scan) (report.Gate, error) { return e.Finalize(ctx, s) },
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, res.Scan.Close()) })
	return res
}

func TestFinalizeInAScan(t *testing.T) {
	p, err := policy.Parse("vet-policy.yml", []byte(policyFile))
	require.NoError(t, err)
	res := scan(t, policy.NewEvaluator(p, policy.Options{Now: func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) }}))
	ctx := context.Background()

	tr := res.Scan.Trailer()
	require.NotNil(t, tr)
	assert.Equal(t, report.GateFail, tr.Gate.Outcome)
	assert.Equal(t, []string{"no-evil"}, tr.Gate.Rules)
	assert.Len(t, tr.Gate.FindingIDs, 1)
	assert.Equal(t, "vet-policy.yml", tr.Gate.Policy)
	assert.Equal(t, 2, tr.Summary.Findings)
	assert.Equal(t, 1, tr.Summary.Suppressed, "the suppressed finding stays in the report")
	assert.Equal(t, string(report.GateFail), res.Entry.Gate)

	byName := map[string]*finding.Finding{}
	for f, err := range res.Scan.Findings(ctx, plugin.FindingQuery{IncludeSuppressed: true}) {
		require.NoError(t, err)
		byName[f.Subject.Package.Name] = f
	}
	require.Len(t, byName, 3)
	assert.Equal(t, []string{"no-evil"}, byName["evil"].Gate.Rules)
	require.True(t, byName["requests"].Suppressed())
	assert.Equal(t, "Reviewed.", byName["requests"].Suppression.Reason)
	assert.Equal(t, &finding.GateRecord{Action: finding.GateActionWarn, Rules: []string{"note-flask"}}, byName["flask"].Gate)
	assert.False(t, byName["flask"].Suppressed(), "an expired suppression does not match")

	var diags []*report.Diagnostic
	for rec, err := range res.Scan.Records(ctx) {
		require.NoError(t, err)
		if rec.Diagnostic != nil {
			diags = append(diags, rec.Diagnostic)
		}
	}
	require.Len(t, diags, 1)
	assert.Equal(t, policy.CodeSuppressionExpired, diags[0].Code)
}

func TestFinalizePackageRules(t *testing.T) {
	p, err := policy.Parse("vet-policy.yml", []byte(`version: 2
rules:
  - id: no-evil
    description: The evil package is not allowed.
    when: package.is("EVIL")
    action: fail
    severity: high
    help: Remove it.
  - id: note-flask
    when: package.name == "flask"
    action: warn
  - id: every-high
    when: finding.severity == "high"
    action: fail
suppressions:
  - id: f-0000000000000000
    reason: unused
`))
	require.NoError(t, err)
	assert.Equal(t, policy.ScopePackage, p.Rules[0].Scope())
	assert.Equal(t, policy.ScopeFinding, p.Rules[2].Scope())
	res := scan(t, policy.NewEvaluator(p, policy.Options{}))
	ctx := context.Background()

	tr := res.Scan.Trailer()
	require.NotNil(t, tr)
	assert.Equal(t, report.GateFail, tr.Gate.Outcome)
	assert.Equal(t, []string{"no-evil"}, tr.Gate.Rules, "every-high does not evaluate the high finding of a package rule")
	assert.Equal(t, 5, tr.Summary.Findings, "three control findings and two package rule findings")

	var rules []*finding.Finding
	for f, err := range res.Scan.Findings(ctx, plugin.FindingQuery{ControlID: policy.RuleControl}) {
		require.NoError(t, err)
		rules = append(rules, f)
	}
	require.Len(t, rules, 2)
	evil, flask := rules[0], rules[1]
	assert.Equal(t, "The evil package is not allowed.", evil.Title)
	assert.Equal(t, finding.SeverityHigh, evil.Severity)
	assert.Equal(t, finding.FamilyPolicy, evil.Family)
	assert.Equal(t, &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"no-evil"}, Help: "Remove it."}, evil.Gate)
	assert.Equal(t, "The package matches policy rule note-flask", flask.Title)
	assert.Equal(t, finding.SeverityInfo, flask.Severity)
	assert.Equal(t, &finding.GateRecord{Action: finding.GateActionWarn, Rules: []string{"note-flask"}}, flask.Gate)

	for f, err := range res.Scan.Findings(ctx, plugin.FindingQuery{ControlID: "every"}) {
		require.NoError(t, err)
		assert.Nil(t, f.Gate, "a package rule does not run on the findings of %s", f.Subject.Package.Name)
	}
}

func TestFinalizeWithNoGate(t *testing.T) {
	res := scan(t, policy.NewEvaluator(nil, policy.Options{}))
	tr := res.Scan.Trailer()
	require.NotNil(t, tr)
	assert.Equal(t, report.Gate{Outcome: report.GateNone}, tr.Gate, "a plain scan has no gate")
	assert.Equal(t, 3, tr.Summary.Findings)
}

func TestFinalizeSeverityGate(t *testing.T) {
	res := scan(t, policy.NewEvaluator(nil, policy.Options{FailOn: report.FailOn(finding.SeverityCritical)}))
	tr := res.Scan.Trailer()
	require.NotNil(t, tr)
	assert.Equal(t, report.GateFail, tr.Gate.Outcome)
	assert.Equal(t, report.FailOn(finding.SeverityCritical), tr.Gate.FailOn)

	p, err := policy.Parse("p.yml", []byte("version: 2\nsuppressions:\n  - purl: pkg:pypi/evil\n    reason: r\n"))
	require.NoError(t, err)
	res = scan(t, policy.NewEvaluator(p, policy.Options{FailOn: report.FailOn(finding.SeverityCritical)}))
	assert.Equal(t, report.GatePass, res.Scan.Trailer().Gate.Outcome, "the gate ignores the suppressed critical finding")
}

type docs []plugin.PolicyDoc

func (d docs) Policies(context.Context) ([]plugin.PolicyDoc, error) { return d, nil }

type unavailable struct{}

func (unavailable) Policies(context.Context) ([]plugin.PolicyDoc, error) {
	return nil, fmt.Errorf("tenant policy: %w", plugin.ErrUnavailable)
}

type broken struct{}

func (broken) Policies(context.Context) ([]plugin.PolicyDoc, error) { return nil, errors.New("disk") }

func TestUnavailablePolicySource(t *testing.T) {
	ctx := context.Background()
	_, err := policy.NewFromSources(ctx, policy.Options{}, broken{})
	require.Error(t, err, "a source that fails for another reason stops the scan")

	local := docs{{Name: "vet-policy.yml", Content: []byte(policyFile)}}
	e, err := policy.NewFromSources(ctx, policy.Options{}, local, unavailable{})
	require.NoError(t, err)
	res := scan(t, e)

	tr := res.Scan.Trailer()
	require.NotNil(t, tr)
	assert.Equal(t, report.GateFail, tr.Gate.Outcome, "the local policy still applies")
	var codes []string
	for rec, err := range res.Scan.Records(ctx) {
		require.NoError(t, err)
		if rec.Diagnostic != nil {
			codes = append(codes, rec.Diagnostic.Code)
		}
	}
	assert.Contains(t, codes, policy.CodeSourceUnavailable)
}

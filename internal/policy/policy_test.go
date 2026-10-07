package policy

import (
	"strconv"
	"testing"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

const valid = `version: 2
rules:
  - id: no-fresh-packages
    when: package.days_since_publish < 5
    action: fail
  - id: workflow-risk
    description: Workflow findings need a review.
    when: finding.control_id in ["dangerous-trigger", "template-injection"]
    action: warn
suppressions:
  - purl: pkg:npm/left-pad-utils@3.2.1
    control: dependency-cooldown
    reason: "Reviewed. The maintainer published a fix."
    expires: 2026-11-01
  - id: f-0123456789abcdef
    reason: A false positive.
`

func TestParse(t *testing.T) {
	p, err := Parse("vet-policy.yml", []byte(valid))
	require.NoError(t, err)
	assert.Equal(t, []string{"vet-policy.yml"}, p.Sources)
	require.Len(t, p.Rules, 2)
	assert.Equal(t, ActionWarn, p.Rules[1].Action)
	require.Len(t, p.Suppressions, 2)
	require.NotNil(t, p.Suppressions[0].expires)
	assert.Equal(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), *p.Suppressions[0].expires)
	assert.Equal(t, "vet-policy.yml#suppressions[1]", p.Suppressions[1].ref)
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{name: "empty file", doc: "", want: []string{"version is 0"}},
		{name: "version 1", doc: "version: 1\n", want: []string{"version is 1"}},
		{name: "unknown key", doc: "version: 2\nfilters: []\n", want: []string{`p.yml line 2: "filters" is not a field of a policy file. A policy file has version, rules and suppressions.`}},
		{name: "not yaml", doc: "version: [\n", want: []string{"p.yml"}},
		{
			name: "bad rules",
			doc:  "version: 2\nrules:\n  - when: 'true'\n    action: block\n  - id: a\n    action: fail\n  - id: a\n    when: package.\n    action: warn\n",
			want: []string{"rules[0]: id is empty", `rules[0]: action is "block"`, "rules[1]: when is empty", `rules[2]: id "a" is not unique`, "rules[2]: when: ERROR"},
		},
		{
			name: "bad suppressions",
			doc:  "version: 2\nsuppressions:\n  - reason: x\n  - control: c\n  - purl: 'not a purl'\n    reason: x\n  - control: c\n    reason: x\n    expires: next week\n",
			want: []string{"suppressions[0]: set id, purl or control", "suppressions[1]: reason is empty", "suppressions[2]: parse PURL", `suppressions[3]: expires is "next week"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("p.yml", []byte(tc.doc))
			require.Error(t, err)
			ue, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, CodeInvalid, ue.Code())
			for _, w := range tc.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}
}

func TestYAMLErrorsNameTheFileAndTheLine(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "unknown rule field",
			doc:  "version: 2\nrules:\n  - id: r1\n    fail: true\n    when: 'true'\n    action: fail\n",
			want: `bad.yml line 4: "fail" is not a field of a rule. A rule has id, description, when, action, help and link.`,
		},
		{
			name: "unknown suppression field",
			doc:  "version: 2\nsuppressions:\n  - control: c\n    why: x\n",
			want: `bad.yml line 4: "why" is not a field of a suppression. A suppression has id, purl, control, reason and expires.`,
		},
		{
			name: "two errors",
			doc:  "version: 2\nfilters: []\nrules:\n  - id: r1\n    fail: true\n",
			want: "bad.yml line 2: \"filters\" is not a field of a policy file. A policy file has version, rules and suppressions.\n" +
				`bad.yml line 5: "fail" is not a field of a rule. A rule has id, description, when, action, help and link.`,
		},
		{name: "wrong type", doc: "version: two\n", want: `bad.yml line 1: the value "two" must be a whole number`},
		{name: "rules not a list", doc: "version: 2\nrules:\n  id: r1\n", want: "bad.yml line 3: the value must be a list"},
		{name: "syntax", doc: "version: [\n", want: "bad.yml line 1: did not find expected node content"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]plugin.PolicyDoc{{Name: "bad.yml", Content: []byte(tc.doc)}})
			ue, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, tc.want, ue.HumanError())
			assert.NotContains(t, err.Error(), CodeInvalid+": "+CodeInvalid, "the code shows once")
		})
	}
}

func TestLoadMerges(t *testing.T) {
	a := plugin.PolicyDoc{Name: "a.yml", Content: []byte("version: 2\nrules:\n  - id: r1\n    when: 'true'\n    action: warn\n")}
	b := plugin.PolicyDoc{Name: "b.yml", Content: []byte("version: 2\nrules:\n  - id: r2\n    when: 'true'\n    action: fail\nsuppressions:\n  - control: c\n    reason: x\n")}
	p, err := Load([]plugin.PolicyDoc{a, b})
	require.NoError(t, err)
	assert.Equal(t, []string{"a.yml", "b.yml"}, p.Sources)
	assert.Len(t, p.Rules, 2)
	assert.Len(t, p.Suppressions, 1)

	_, err = Load([]plugin.PolicyDoc{a, a})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `a.yml: rule "r1" is also in a.yml`)
}

func packageFinding(control string, sev finding.Severity, name, version string, published *time.Time) (*finding.Finding, *model.Package) {
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, name, version), Direct: true}
	if published != nil {
		p.Insight = &model.Insight{PublishedAt: published}
	}
	f := finding.ForPackage(finding.Meta{ControlID: control, Family: finding.FamilyCooldown, Severity: sev, Title: "t"}, "package-lock.json", p, finding.Key{})
	return &f, p
}

func TestApply(t *testing.T) {
	p, err := Parse("vet-policy.yml", []byte(valid))
	require.NoError(t, err)
	fresh := now.Add(-48 * time.Hour)
	old := now.Add(-400 * 24 * time.Hour)

	type want struct {
		fail       bool
		failRules  []string
		gate       *finding.Gate
		suppressed bool
		expired    int
	}
	cases := []struct {
		name    string
		now     time.Time
		failOn  finding.Severity
		control string
		sev     finding.Severity
		pkg     string
		version string
		pub     *time.Time
		want    want
	}{
		{
			name: "fail rule", control: "vulnerability", sev: finding.SeverityLow, pkg: "a", version: "1.0.0", pub: &fresh,
			want: want{fail: true, failRules: []string{"no-fresh-packages"}, gate: &finding.Gate{Action: finding.GateActionFail, Rules: []string{"no-fresh-packages"}}},
		},
		{name: "no rule matches", control: "vulnerability", sev: finding.SeverityLow, pkg: "a", version: "1.0.0", pub: &old},
		{
			name: "warn rule", control: "dangerous-trigger", sev: finding.SeverityHigh, pkg: "a", version: "1.0.0", pub: &old,
			want: want{gate: &finding.Gate{Action: finding.GateActionWarn, Rules: []string{"workflow-risk"}}},
		},
		{
			name: "severity gate", failOn: finding.SeverityHigh, control: "dangerous-trigger", sev: finding.SeverityHigh, pkg: "a", version: "1.0.0",
			want: want{fail: true, gate: &finding.Gate{Action: finding.GateActionFail, FailOn: "high"}},
		},
		{name: "below the severity gate", failOn: finding.SeverityCritical, control: "vulnerability", sev: finding.SeverityHigh, pkg: "a", version: "1.0.0"},
		{
			name: "suppressed", control: "dependency-cooldown", sev: finding.SeverityHigh, pkg: "left-pad-utils", version: "3.2.1", pub: &fresh, failOn: finding.SeverityLow,
			want: want{suppressed: true},
		},
		{
			name: "other version is not suppressed", control: "dependency-cooldown", sev: finding.SeverityHigh, pkg: "left-pad-utils", version: "3.2.2", pub: &fresh,
			want: want{fail: true, failRules: []string{"no-fresh-packages"}, gate: &finding.Gate{Action: finding.GateActionFail, Rules: []string{"no-fresh-packages"}}},
		},
		{
			name: "expired suppression", now: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), control: "dependency-cooldown", sev: finding.SeverityHigh, pkg: "left-pad-utils", version: "3.2.1",
			pub: &fresh, want: want{fail: true, failRules: []string{"no-fresh-packages"}, gate: &finding.Gate{Action: finding.GateActionFail, Rules: []string{"no-fresh-packages"}}, expired: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := now
			if !tc.now.IsZero() {
				at = tc.now
			}
			if tc.pub != nil && !tc.now.IsZero() {
				shifted := tc.pub.Add(tc.now.Sub(now))
				tc.pub = &shifted
			}
			e := NewEvaluator(p, Options{FailOn: report.FailOn(tc.failOn), Now: func() time.Time { return at }})
			f, pkg := packageFinding(tc.control, tc.sev, tc.pkg, tc.version, tc.pub)
			out := e.Apply(f, pkg, nil)
			assert.Empty(t, out.Errors)
			assert.Equal(t, tc.want.fail, out.Fail)
			assert.Equal(t, tc.want.failRules, out.FailRules)
			assert.Equal(t, tc.want.gate, f.Gate)
			assert.Equal(t, tc.want.suppressed, f.Suppressed())
			assert.Len(t, out.Expired, tc.want.expired)
		})
	}
}

func TestApplySuppressionSelectors(t *testing.T) {
	f, pkg := packageFinding("malware", finding.SeverityCritical, "evil", "1.0.0", nil)
	file := finding.ForFile(finding.Meta{ControlID: "unpinned-action", Family: finding.FamilyWorkflow, Severity: finding.SeverityMedium, Title: "t"},
		finding.Locus{Path: "ci.yml", StartLine: 3, Snippet: "uses: a/b@v1"}, finding.Key{Discriminator: "a/b"})
	cases := []struct {
		name string
		s    string
		f    *finding.Finding
		want bool
	}{
		{name: "finding id", s: "id: " + f.ID, f: f, want: true},
		{name: "other finding id", s: "id: f-0000000000000000", f: f},
		{name: "purl with no version", s: "purl: pkg:npm/evil", f: f, want: true},
		{name: "purl of another package", s: "purl: pkg:npm/good", f: f},
		{name: "control", s: "control: malware", f: f, want: true},
		{name: "control and purl", s: "control: malware\n    purl: pkg:npm/evil@2.0.0", f: f},
		{name: "purl on a file finding", s: "purl: pkg:npm/evil", f: &file},
		{name: "control on a file finding", s: "control: unpinned-action", f: &file, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse("p.yml", []byte("version: 2\nsuppressions:\n  - reason: r\n    "+tc.s+"\n"))
			require.NoError(t, err)
			out := NewEvaluator(p, Options{FailOn: report.FailOn(finding.SeverityLow), Now: func() time.Time { return now }}).Apply(tc.f, pkg, nil)
			assert.Equal(t, tc.want, tc.f.Suppressed())
			assert.Equal(t, !tc.want, out.Fail, "the gate ignores a suppressed finding")
		})
	}
}

func TestApplyClearsAnEarlierRun(t *testing.T) {
	f, pkg := packageFinding("malware", finding.SeverityCritical, "evil", "1.0.0", nil)
	f.Suppression = &finding.Suppression{Reason: "old"}
	f.Gate = &finding.Gate{Action: finding.GateActionWarn, Rules: []string{"old-rule"}}
	NewEvaluator(nil, Options{}).Apply(f, pkg, nil)
	assert.False(t, f.Suppressed())
	assert.Nil(t, f.Gate)
}

func TestApplyRuleError(t *testing.T) {
	p, err := Parse("p.yml", []byte("version: 2\nrules:\n  - id: bad\n    when: int(finding.title) > 0\n    action: fail\n"))
	require.NoError(t, err)
	f, pkg := packageFinding("malware", finding.SeverityCritical, "evil", "1.0.0", nil)
	out := NewEvaluator(p, Options{}).Apply(f, pkg, nil)
	require.Len(t, out.Errors, 1)
	assert.Contains(t, out.Errors[0].Error(), "rule bad")
	assert.True(t, out.Fail, "a fail rule that does not evaluate fails the gate")
	assert.Equal(t, []string{"bad"}, out.BrokenRules)
	assert.Equal(t, &finding.Gate{Action: finding.GateActionFail, Rules: []string{"bad"}}, f.Gate, "a fail rule that does not evaluate blocks the finding")

	warn, err := Parse("p.yml", []byte("version: 2\nrules:\n  - id: bad\n    when: int(finding.title) > 0\n    action: warn\n"))
	require.NoError(t, err)
	out = NewEvaluator(warn, Options{}).Apply(f, pkg, nil)
	require.Len(t, out.Errors, 1)
	assert.False(t, out.Fail, "a warn rule that does not evaluate is a diagnostic only")

	gate := NewEvaluator(p, Options{}).NewGate()
	gate.Add(f, NewEvaluator(p, Options{}).Apply(f, pkg, nil))
	assert.Equal(t, []string{"bad"}, gate.Result().Rules, "the gate names the rule that did not run")
}

// TestSuppressionMatchesEverySpelling checks that a suppression PURL names
// the package under the rule of the ecosystem.
func TestSuppressionMatchesEverySpelling(t *testing.T) {
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "python.dateutil", "2.9.0")}
	cases := []struct {
		purl string
		want bool
	}{
		{"pkg:pypi/Python_Dateutil@2.9", true},
		{"pkg:pypi/python-dateutil", true},
		{"pkg:pypi/python-dateutil@2.8.0", false},
		{"pkg:pypi/dateutil", false},
	}
	for _, tc := range cases {
		t.Run(tc.purl, func(t *testing.T) {
			f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "t"}, "requirements.txt", p, finding.Key{})
			pol, err := Parse("p.yml", []byte("version: 2\nsuppressions:\n  - reason: r\n    purl: "+tc.purl+"\n"))
			require.NoError(t, err)
			NewEvaluator(pol, Options{Now: func() time.Time { return now }}).Apply(&f, p, nil)
			assert.Equal(t, tc.want, f.Suppressed())
		})
	}
}

func TestRuleLink(t *testing.T) {
	cases := []struct {
		name, link string
		ok         bool
	}{
		{"https", "https://wiki.example.com/security", true},
		{"http", "http://wiki.example.com", true},
		{"script", "javascript:alert(1)", false},
		{"relative", "/security", false},
		{"no host", "https://", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("p.yml", []byte("version: 2\nrules:\n  - id: r\n    when: \"true\"\n    action: warn\n    link: "+strconv.Quote(tc.link)+"\n"))
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "use an http or https URL")
		})
	}
}

func TestApplyGateRecord(t *testing.T) {
	p, err := Parse("p.yml", []byte(`version: 2
rules:
  - id: note
    when: "true"
    action: warn
    help: Read the note.
  - id: block-malware
    when: finding.control_id == "malware"
    action: fail
    help: Remove the package.
    link: https://wiki.example.com/malware
  - id: block-critical
    when: finding.severity == "critical"
    action: fail
`))
	require.NoError(t, err)
	cases := []struct {
		name    string
		control string
		failOn  report.FailOn
		want    *finding.Gate
	}{
		{
			name: "two fail rules and --fail-on", control: "malware", failOn: report.FailOnAttacks,
			want: &finding.Gate{Action: finding.GateActionFail, Rules: []string{"block-malware", "block-critical"}, FailOn: "attacks", Help: "Remove the package.", Link: "https://wiki.example.com/malware"},
		},
		{
			name: "one fail rule", control: "vulnerability",
			want: &finding.Gate{Action: finding.GateActionFail, Rules: []string{"block-critical"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, pkg := packageFinding(tc.control, finding.SeverityCritical, "evil", "1.0.0", nil)
			NewEvaluator(p, Options{FailOn: tc.failOn, Attacks: []string{"malware"}, Now: func() time.Time { return now }}).Apply(f, pkg, nil)
			assert.Equal(t, tc.want, f.Gate)
		})
	}

	f, pkg := packageFinding("vulnerability", finding.SeverityLow, "a", "1.0.0", nil)
	NewEvaluator(p, Options{}).Apply(f, pkg, nil)
	assert.Equal(t, &finding.Gate{Action: finding.GateActionWarn, Rules: []string{"note"}, Help: "Read the note."}, f.Gate)
	assert.Equal(t, "Warned by", f.Gate.Label())
	assert.Equal(t, "policy rule note", f.Gate.Cause())
}

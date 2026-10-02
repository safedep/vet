package policy

import (
	"testing"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
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
		{name: "unknown key", doc: "version: 2\nfilters: []\n", want: []string{"field filters not found"}},
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
	p := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: name, Version: version}, Direct: true}
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
		policyRule string
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
			want: want{fail: true, failRules: []string{"no-fresh-packages"}, policyRule: "no-fresh-packages"},
		},
		{name: "no rule matches", control: "vulnerability", sev: finding.SeverityLow, pkg: "a", version: "1.0.0", pub: &old},
		{
			name: "warn rule", control: "dangerous-trigger", sev: finding.SeverityHigh, pkg: "a", version: "1.0.0", pub: &old,
			want: want{policyRule: "workflow-risk"},
		},
		{
			name: "severity gate", failOn: finding.SeverityHigh, control: "dangerous-trigger", sev: finding.SeverityHigh, pkg: "a", version: "1.0.0",
			want: want{fail: true, policyRule: "workflow-risk"},
		},
		{name: "below the severity gate", failOn: finding.SeverityCritical, control: "vulnerability", sev: finding.SeverityHigh, pkg: "a", version: "1.0.0"},
		{
			name: "suppressed", control: "dependency-cooldown", sev: finding.SeverityHigh, pkg: "left-pad-utils", version: "3.2.1", pub: &fresh, failOn: finding.SeverityLow,
			want: want{policyRule: "no-fresh-packages", suppressed: true},
		},
		{
			name: "other version is not suppressed", control: "dependency-cooldown", sev: finding.SeverityHigh, pkg: "left-pad-utils", version: "3.2.2", pub: &fresh,
			want: want{fail: true, failRules: []string{"no-fresh-packages"}, policyRule: "no-fresh-packages"},
		},
		{
			name: "expired suppression", now: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), control: "dependency-cooldown", sev: finding.SeverityHigh, pkg: "left-pad-utils", version: "3.2.1",
			pub: &fresh, want: want{fail: true, failRules: []string{"no-fresh-packages"}, policyRule: "no-fresh-packages", expired: 1},
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
			e := NewEvaluator(p, Options{FailOn: tc.failOn, Now: func() time.Time { return at }})
			f, pkg := packageFinding(tc.control, tc.sev, tc.pkg, tc.version, tc.pub)
			out := e.Apply(f, pkg, nil)
			assert.Empty(t, out.Errors)
			assert.Equal(t, tc.want.fail, out.Fail)
			assert.Equal(t, tc.want.failRules, out.FailRules)
			assert.Equal(t, tc.want.policyRule, f.PolicyRule)
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
			out := NewEvaluator(p, Options{FailOn: finding.SeverityLow, Now: func() time.Time { return now }}).Apply(tc.f, pkg, nil)
			assert.Equal(t, tc.want, tc.f.Suppressed())
			assert.Equal(t, !tc.want, out.Fail, "the gate ignores a suppressed finding")
		})
	}
}

func TestApplyClearsAnEarlierRun(t *testing.T) {
	f, pkg := packageFinding("malware", finding.SeverityCritical, "evil", "1.0.0", nil)
	f.Suppression = &finding.Suppression{Reason: "old"}
	f.PolicyRule = "old-rule"
	NewEvaluator(nil, Options{}).Apply(f, pkg, nil)
	assert.False(t, f.Suppressed())
	assert.Empty(t, f.PolicyRule)
}

func TestApplyRuleError(t *testing.T) {
	p, err := Parse("p.yml", []byte("version: 2\nrules:\n  - id: bad\n    when: int(finding.title) > 0\n    action: fail\n"))
	require.NoError(t, err)
	f, pkg := packageFinding("malware", finding.SeverityCritical, "evil", "1.0.0", nil)
	out := NewEvaluator(p, Options{}).Apply(f, pkg, nil)
	require.Len(t, out.Errors, 1)
	assert.Contains(t, out.Errors[0].Error(), "rule bad")
	assert.False(t, out.Fail, "a rule that does not evaluate does not fail the gate")
}

package policy

import (
	"testing"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/report"
)

func TestGate(t *testing.T) {
	p, err := Parse("p.yml", []byte("version: 2\nrules:\n  - id: crit\n    when: finding.severity == 'critical'\n    action: fail\n"))
	require.NoError(t, err)
	at := func() time.Time { return now }
	crit, critPkg := packageFinding("malware", finding.SeverityCritical, "evil", "1.0.0", nil)
	low, lowPkg := packageFinding("vulnerability", finding.SeverityLow, "a", "1.0.0", nil)

	cases := []struct {
		name string
		e    *Evaluator
		want report.Gate
	}{
		{name: "no gate", e: NewEvaluator(nil, Options{Now: at}), want: report.Gate{Outcome: report.GateNone}},
		{
			name: "severity fail", e: NewEvaluator(nil, Options{FailOn: report.FailOn(finding.SeverityHigh), Now: at}),
			want: report.Gate{Outcome: report.GateFail, FailOn: report.FailOn(finding.SeverityHigh), FindingIDs: []string{crit.ID}},
		},
		{
			name: "attacks fail", e: NewEvaluator(nil, Options{FailOn: report.FailOnAttacks, Attacks: []string{"malware"}, Now: at}),
			want: report.Gate{Outcome: report.GateFail, FailOn: report.FailOnAttacks, FindingIDs: []string{crit.ID}},
		},
		{
			name: "attacks ignore severity", e: NewEvaluator(nil, Options{FailOn: report.FailOnAttacks, Attacks: []string{"impostor-commit"}, Now: at}),
			want: report.Gate{Outcome: report.GatePass, FailOn: report.FailOnAttacks},
		},
		{
			name: "policy fail", e: NewEvaluator(p, Options{Now: at}),
			want: report.Gate{Outcome: report.GateFail, Policy: "p.yml", Rules: []string{"crit"}, FindingIDs: []string{crit.ID}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := tc.e.NewGate()
			g.Add(crit, tc.e.Apply(crit, critPkg, nil))
			g.Add(low, tc.e.Apply(low, lowPkg, nil))
			assert.Equal(t, tc.want, g.Result())
		})
	}

	g := NewEvaluator(p, Options{Now: at}).NewGate()
	assert.Equal(t, report.Gate{Outcome: report.GatePass, Policy: "p.yml"}, g.Result(), "a policy with no failing finding passes")
}

func TestResolveSettings(t *testing.T) {
	cases := []struct {
		name               string
		failOn, policyFlag string
		cfg                config.PolicyConfig
		want               Settings
		wantErr            bool
	}{
		{name: "nothing set"},
		{name: "attacks", failOn: "attacks", want: Settings{FailOn: report.FailOnAttacks}},
		{name: "config", cfg: config.PolicyConfig{FailOn: "HIGH", File: "p.yml"}, want: Settings{FailOn: report.FailOn(finding.SeverityHigh), File: "p.yml"}},
		{name: "flags win", failOn: "critical", policyFlag: "q.yml", cfg: config.PolicyConfig{FailOn: "low", File: "p.yml"}, want: Settings{FailOn: report.FailOn(finding.SeverityCritical), File: "q.yml"}},
		{name: "bad severity", failOn: "severe", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ResolveSettings(tc.failOn, tc.policyFlag, tc.cfg)
			if tc.wantErr {
				ue, ok := usefulerror.AsUsefulError(err)
				require.True(t, ok)
				assert.Equal(t, CodeFailOn, ue.Code())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, s)
		})
	}
}

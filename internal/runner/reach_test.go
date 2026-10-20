package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/internal/plugins/sources/purl"
	"github.com/safedep/vet/v2/report"
)

func TestCodeAnalysisOf(t *testing.T) {
	off, on := false, true
	plugins := func(enabled *bool, options map[string]any) map[string]config.PluginConfig {
		return map[string]config.PluginConfig{codeusage.Name: {Enabled: enabled, Options: options}}
	}
	// A build with no CGO turns the default off, and an explicit enabled
	// keeps the enricher, so its diagnostic says why no code is read.
	defaultOn, defaultStatus := codeusage.Available(), report.ReachStatus("")
	if !defaultOn {
		defaultStatus = report.ReachUnavailable
	}
	cases := []struct {
		name    string
		plugins map[string]config.PluginConfig
		flag    string
		source  bool
		want    codeAnalysis
		usage   bool
	}{
		{name: "on by default at function level", want: codeAnalysis{on: defaultOn, budget: codeusage.DefaultBudget, reach: report.ReachInfo{Level: report.ReachFunction, Status: defaultStatus}}},
		{
			name: "the flag overrides the config", plugins: plugins(nil, map[string]any{"reach": "function", "budget": "90s"}), flag: "import",
			want: codeAnalysis{on: defaultOn, budget: 90 * time.Second, reach: report.ReachInfo{Level: report.ReachImport, Status: defaultStatus}},
		},
		{name: "reach off keeps the code analysis", flag: "off", want: codeAnalysis{on: defaultOn, budget: codeusage.DefaultBudget, reach: report.ReachInfo{Level: report.ReachOff, Status: defaultStatus}}},
		{name: "enabled false turns off all code analysis", plugins: plugins(&off, nil), want: codeAnalysis{budget: codeusage.DefaultBudget, reach: report.ReachInfo{Level: report.ReachOff}}},
		{name: "an explicit enabled keeps the enricher", plugins: plugins(&on, nil), want: codeAnalysis{on: true, budget: codeusage.DefaultBudget, reach: report.ReachInfo{Level: report.ReachFunction}}},
		{name: "a replaced source reads no code", source: true, want: codeAnalysis{budget: codeusage.DefaultBudget, reach: report.ReachInfo{Level: report.ReachOff}}},
		{name: "a bad flag", flag: "deep", usage: true},
		{name: "a bad budget", plugins: plugins(nil, map[string]any{"budget": "soon"}), usage: true},
		{name: "a bad level", plugins: plugins(nil, map[string]any{"reach": "all"}), usage: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Options{Reach: c.flag}
			if c.source {
				o.Source = purl.New(purl.Options{Target: "pkg:npm/a@1.0.0"})
			}
			got, err := codeAnalysisOf(&config.Config{Plugins: c.plugins}, o)
			if c.usage {
				require.Error(t, err)
				assert.Equal(t, app.ExitUsage, app.ExitCode(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestReachFlagIsLockable(t *testing.T) {
	assert.Contains(t, Options{Reach: "off"}.lockableKeys(false), codeusage.ReachKey)
	assert.NotContains(t, Options{}.lockableKeys(false), codeusage.ReachKey)
}

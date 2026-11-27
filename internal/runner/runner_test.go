package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/plugins/builtin"
	"github.com/safedep/vet/v2/internal/plugins/controls/cooldown"
	"github.com/safedep/vet/v2/internal/plugins/controls/workflow"
	"github.com/safedep/vet/v2/internal/plugins/enrichers"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/insights"
	"github.com/safedep/vet/v2/internal/plugins/sinks/plain"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/technique"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/view"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func TestLockableKeys(t *testing.T) {
	cases := []struct {
		name      string
		o         Options
		ephemeral bool
		want      []string
	}{
		{"no flag", Options{}, false, nil},
		{"ephemeral", Options{}, true, []string{"state.dir", "cache.dir"}},
		{"gate", Options{FailOn: "high", Policy: "p.yml"}, false, []string{"policy.fail_on", "policy.file"}},
		{
			"scan flags",
			Options{Strict: true, Exclude: []string{"docs"}, CooldownDays: 7},
			false,
			[]string{"scan.strict", "scan.exclude", "plugins.dependency-cooldown.options.days"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.o.lockableKeys(tc.ephemeral))
		})
	}
}

func TestOutcome(t *testing.T) {
	cases := []struct {
		name              string
		renderErr, runErr error
		want              int
	}{
		{"clean", nil, nil, app.ExitOK},
		{"gate", app.ErrGateFailed, nil, app.ExitGateFailed},
		{"strict", nil, engine.ErrStrict, app.ExitRuntime},
		{"strict and gate", app.ErrGateFailed, engine.ErrStrict, app.ExitRuntime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := outcome(tc.renderErr, tc.runErr)
			assert.Equal(t, tc.want, app.ExitCode(err))
			if tc.runErr != nil {
				assert.ErrorContains(t, err, CodeStrict, "the strict message prints")
			}
		})
	}
}

func TestRetentionSkipsAStoppedScan(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(context.Background(), state.Options{StateDir: filepath.Join(root, "state")})
	require.NoError(t, err)
	cache, err := state.OpenCache(context.Background(), filepath.Join(root, "cache"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	require.NoError(t, cache.Close())

	var stderr bytes.Buffer
	prev := output.CurrentMode()
	output.SetMode(output.Plain)
	output.SetWriters(os.Stdout, &stderr)
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetWriters(os.Stdout, os.Stderr)
	})

	cases := []struct {
		name    string
		stopped bool
		warns   bool
	}{
		{"stopped", true, false},
		{"completed", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stderr.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.stopped {
				cancel()
			}
			cfg := config.Default()
			applyRetention(ctx, &cfg, store, cache)
			if tc.warns {
				assert.Contains(t, stderr.String(), "retention:", "a closed store fails, so the test sees that retention ran")
				return
			}
			assert.Empty(t, stderr.String())
		})
	}
}

func TestRenderPrintsTheReportStepBeforeTheReport(t *testing.T) {
	var term bytes.Buffer
	prev := output.CurrentMode()
	output.SetMode(output.Plain)
	output.SetWriters(&term, &term)
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetWriters(os.Stdout, os.Stderr)
	})
	sink, err := plain.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	v := view.NewScan(view.Options{Target: "."})
	v.Stage(engine.StageReport, 4, 4)

	require.NoError(t, Render(context.Background(), plugintest.SampleReport(), v, []engine.Output{{Format: plain.Name, Sink: sink}}))

	step := strings.Index(term.String(), "[INFO] Report\n")
	require.GreaterOrEqual(t, step, 0, term.String())
	assert.Equal(t, 0, step, "the step line comes before the report:\n%s", term.String())
}

func TestPackagesOf(t *testing.T) {
	cases := []struct {
		name    string
		flag    string
		config  string
		baseRef string
		want    model.Packages
		err     string
	}{
		{name: "default", want: ""},
		{name: "flag", flag: "installed", want: model.PackagesInstalled},
		{name: "config", config: "all", want: model.PackagesAll},
		{name: "flag over config", flag: "declared", config: "all", want: model.PackagesDeclared},
		{name: "bad value", flag: "everything", err: `--packages "everything" is not valid`},
		{name: "base ref with installed", flag: "all", baseRef: "main", err: "--base-ref reads declared packages only"},
		{name: "base ref with declared", flag: "declared", baseRef: "main", want: model.PackagesDeclared},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Scan: config.ScanConfig{Packages: tc.config}}
			got, err := packagesOf(Options{Packages: tc.flag, BaseRef: tc.baseRef}, cfg)
			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPackagesFor(t *testing.T) {
	cases := []struct {
		set  model.Packages
		kind plugin.ArtifactKind
		want model.Packages
	}{
		{"", plugin.ArtifactDirectory, model.PackagesDeclared},
		{"", plugin.ArtifactImage, model.PackagesAll},
		{model.PackagesInstalled, plugin.ArtifactDirectory, model.PackagesInstalled},
		{model.PackagesDeclared, plugin.ArtifactImage, model.PackagesDeclared},
		{model.PackagesInstalled, plugin.ArtifactSBOM, model.PackagesDeclared},
		{model.PackagesAll, plugin.ArtifactEndpoint, model.PackagesDeclared},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, packagesFor(tc.set, tc.kind), "%q on %s", tc.set, tc.kind)
	}
}

func TestPluginOriginNamesTheSource(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("plugins:\n  dependency-cooldown:\n    options:\n      days: 9\n"), 0o600))
	cases := []struct {
		name string
		opts config.LoadOptions
		days int
		want string
	}{
		{"default", config.LoadOptions{}, 0, ""},
		{"file", config.LoadOptions{ConfigFile: file, Plugins: builtin.ConfigPlugins()}, 0, "file config.yml"},
		{
			"variable", config.LoadOptions{
				LookupEnv: func(string) (string, bool) { return "", false },
				Environ:   func() []string { return []string{"VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS=4"} },
				Plugins:   builtin.ConfigPlugins(),
			}, 0, "env VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS",
		},
		{"flag over the file", config.LoadOptions{ConfigFile: file, Plugins: builtin.ConfigPlugins()}, 7, "flag --cooldown-days"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.opts.LookupEnv == nil {
				tc.opts.LookupEnv = func(string) (string, bool) { return "", false }
			}
			l, err := config.Load(tc.opts)
			require.NoError(t, err)
			s := settingsOf(&config.Runtime{Loaded: l}, tc.days, true)
			assert.Equal(t, tc.want, s.PluginOrigin(cooldown.Name, "days"))
		})
	}
}

func TestMarkAttacksOfAnOldReport(t *testing.T) {
	malware := &finding.Finding{ID: "f-1", ControlID: "malware"}
	vuln := &finding.Finding{ID: "f-2", ControlID: "vulnerability"}
	marked := &finding.Finding{ID: "f-3", ControlID: "padded-code", Attack: &finding.Attack{Technique: "kept"}}
	d := &report.Document{Records: []report.Record{
		{Kind: report.KindFinding, Finding: malware},
		{Kind: report.KindFinding, Finding: vuln},
		{Kind: report.KindFinding, Finding: marked},
	}}
	require.NoError(t, markAttacks(d))
	want, _ := technique.Attack(technique.MaliciousPackage)
	assert.Equal(t, &want, malware.Attack, "a finding of an attack control in an old report is an attack")
	assert.Nil(t, vuln.Attack)
	assert.Equal(t, "kept", marked.Attack.Technique, "a report that has the field keeps it")
}

func TestEnricherSpecsCarryTheCacheRule(t *testing.T) {
	keep := func(model.Enrichment) bool { return false }
	got := enricherSpecs(&enrichers.Set{Specs: []enrichers.Spec{
		{Name: insights.Name, Version: "1", Keep: keep},
		{Name: "other", Version: "2"},
	}})
	require.Len(t, got, 2)
	require.NotNil(t, got[0].Keep, "the engine gets the cache rule of the enricher")
	assert.False(t, got[0].Keep(model.Enrichment{}))
	assert.True(t, got[0].Prior)
	assert.Nil(t, got[1].Keep, "an enricher with no rule keeps each result")
	assert.False(t, got[1].Prior)
}

func TestTrustsActionsLock(t *testing.T) {
	const ghes = "github:\n  api_url: https://github.acme.internal/api/v3\n"
	option := func(v string) string {
		return "plugins:\n  workflow:\n    options:\n      trust_actions_lock: " + v + "\n"
	}
	ghesRunner := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_API_URL": "https://github.acme.internal/api/v3"}
	cases := []struct {
		name      string
		config    string
		env       map[string]string
		want      bool
		wantLeave bool
		wantErr   bool
	}{
		{name: "GitHub.com", want: true, wantLeave: true},
		{name: "GHE.com", config: "github:\n  api_url: https://api.acme.ghe.com\n", want: true, wantLeave: true},
		{name: "GitHub Enterprise Server", config: ghes},
		{name: "GitHub Actions run on GitHub Enterprise Server", env: ghesRunner},
		{name: "GITHUB_API_URL outside GitHub Actions", env: map[string]string{"GITHUB_API_URL": "https://github.acme.internal/api/v3"}, want: true, wantLeave: true},
		{name: "github.api_url over GITHUB_API_URL", config: "github:\n  api_url: https://api.github.com\n", env: ghesRunner, want: true, wantLeave: true},
		{name: "option set on GitHub Enterprise Server", config: ghes + option("true"), want: true, wantLeave: true},
		{name: "option off on GitHub.com", config: option("false"), want: false, wantLeave: true},
		{name: "option in another letter case", config: "plugins:\n  workflow:\n    options:\n      Trust_Actions_Lock: false\n", want: false, wantLeave: true},
		{name: "option with no value", config: ghes + option("")},
		{name: "option that is not a bool", config: option(`"yes"`), wantErr: true},
		{name: "other workflow option that is not valid", config: "plugins:\n  workflow:\n    enabled: false\n    options:\n      allow_unpinned: ['[']\n", want: true, wantLeave: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yml")
			require.NoError(t, os.WriteFile(file, []byte(tc.config), 0o600))
			l, err := config.Load(config.LoadOptions{ConfigFile: file, LookupEnv: func(string) (string, bool) { return "", false }, Plugins: builtin.ConfigPlugins()})
			require.NoError(t, err)
			rt := &config.Runtime{Loaded: l}
			getenv := func(k string) string { return tc.env[k] }
			got, err := TrustsActionsLock(rt, getenv)
			leave, leaveErr := FixLeavesActionsLock(rt, getenv)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Error(t, leaveErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, leaveErr)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantLeave, leave, "the fix leaves the listed files")
			assert.Equal(t, tc.want, settingsOf(rt, 0, got).PluginOptions(workflow.Name)[workflow.OptionTrustActionsLock])
		})
	}
}

func TestControlsTakeTheBuiltInStateOfTheirPlugin(t *testing.T) {
	off := false
	cfg := &config.Config{Plugins: map[string]config.PluginConfig{"vulnerability": {Enabled: &off}}}
	s := pluginSettings{cfg: cfg}
	assert.False(t, s.PluginEnabled("vulnerability"), "a layer turns a control off")
	assert.True(t, s.PluginEnabled("malware"), "a control with no key is on, as builtin says")
	assert.False(t, s.PluginEnabled("tenant-policy"), "a plugin that is off by default stays off")
}

// TestOutputsGiveTheTableTheModeOfItsDestination draws a table format
// while stderr is a rich terminal. A file and a pipe get plain text. Only
// stdout on a terminal gets rich text.
func TestOutputsGiveTheTableTheModeOfItsDestination(t *testing.T) {
	prev := output.CurrentMode()
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetStdoutTerminal(nil)
		output.SetWidthOverride(0)
	})
	output.SetMode(output.Rich)
	output.SetWidthOverride(120)
	cases := []struct {
		name     string
		terminal bool
		out      string
		reports  []string
		at       int
		rich     bool
	}{
		{name: "file", terminal: true, out: "json", reports: []string{"table=" + filepath.Join(t.TempDir(), "t.txt")}, at: 1},
		{name: "stdout to a pipe", out: "table"},
		{name: "stdout on a terminal", terminal: true, out: "table", rich: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetStdoutTerminal(func() bool { return tc.terminal })
			cfg := config.Default()
			outs, err := Outputs(&cfg, tc.out, tc.reports, nil)
			require.NoError(t, err)
			got := string(plugintest.TestSink(t, outs[tc.at].Sink, plugintest.SampleReport()))
			assert.Equal(t, tc.rich, strings.Contains(got, "╭"), got)
			assert.Equal(t, !tc.rich, strings.Contains(got, "+---"), got)
		})
	}
}

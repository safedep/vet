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

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/plugins/controls/cooldown"
	"github.com/safedep/vet/v2/internal/plugins/sinks/plain"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/view"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestLockableKeys(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want []string
	}{
		{"no flag", Options{}, nil},
		{"gate", Options{FailOn: "high", Policy: "p.yml"}, []string{"policy.fail_on", "policy.file"}},
		{
			"scan flags",
			Options{Strict: true, Exclude: []string{"docs"}, CooldownDays: 7},
			[]string{"scan.strict", "scan.exclude", "plugins.dependency-cooldown.options.days"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.o.lockableKeys())
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
		{"file", config.LoadOptions{ConfigFile: file}, 0, "file config.yml"},
		{
			"variable", config.LoadOptions{
				LookupEnv:   func(string) (string, bool) { return "", false },
				Environ:     func() []string { return []string{"VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS=4"} },
				PluginNames: []string{cooldown.Name},
			}, 0, "env VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS",
		},
		{"flag over the file", config.LoadOptions{ConfigFile: file}, 7, "flag --cooldown-days"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.opts.LookupEnv == nil {
				tc.opts.LookupEnv = func(string) (string, bool) { return "", false }
			}
			l, err := config.Load(tc.opts)
			require.NoError(t, err)
			s := withCooldown(&config.Runtime{Loaded: l}, tc.days)
			assert.Equal(t, tc.want, s.PluginOrigin(cooldown.Name, "days"))
		})
	}
}

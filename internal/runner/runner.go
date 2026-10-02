// Package runner wires a scan from the config of a run: the state, the
// source, the extractors, the enrichers, the controls, the policy, the
// views and the report destinations. The scan and endpoint commands share
// it, because command packages do not import each other.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/usefulerror"
	"golang.org/x/term"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/plugins/cloud/tenantpolicy"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/controls/cooldown"
	"github.com/safedep/vet/v2/internal/plugins/enrichers"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/policysources/file"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/version"
	"github.com/safedep/vet/v2/internal/view"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Options are the inputs of a scan, from the flags of the command.
type Options struct {
	Target  string
	Kind    report.ScanKind
	BaseRef string

	FailOn  string
	Policy  string
	Reports []string

	Strict  bool
	Resume  bool
	Fresh   bool
	NoCache bool
	Exclude []string
	// CooldownDays sets plugins.dependency-cooldown.options.days when it
	// is not zero.
	CooldownDays int

	State state.Flags
}

// hashed are the options that change what a scan stores. A stopped scan
// continues only when they are the same.
type hashed struct {
	BaseRef   string   `json:"base_ref,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
	API       string   `json:"api"`
	Anonymous bool     `json:"anonymous"`
}

// Scan runs a scan, writes the report to its destinations and returns the
// error that sets the exit code: nil, a failed gate, a stop on a signal or
// a runtime error.
func Scan(ctx context.Context, a *app.App, o Options) error {
	rt, err := a.Config(app.ConfigOptions{StateDir: o.State.StateDir, CacheDir: o.State.CacheDir})
	if err != nil {
		return err
	}
	cfg := rt.Config
	for _, w := range rt.Warnings {
		tui.Warning("%s", w)
	}

	gate, err := policy.ResolveSettings(o.FailOn, o.Policy, cfg.Policy)
	if err != nil {
		return err
	}
	outs, err := Outputs(cfg, a.Globals.Output, o.Reports, nil)
	if err != nil {
		return err
	}
	if o.CooldownDays < 0 {
		return app.UsageError("--cooldown-days must be 1 or more", "Set the number of days, for example --cooldown-days 7.")
	}
	creds, err := credentials.Resolve(credentials.FromConfig(cfg.Cloud.Profile, cfg.Cloud.InsecureKeychainFallback, cfg.Cloud.KeychainFile))
	if err != nil {
		return err
	}
	if creds.Warning != "" {
		tui.Warning("%s", creds.Warning)
	}
	src, err := sources.New(o.Target, sources.Options{Tokens: github.DefaultProvider()})
	if err != nil {
		return err
	}
	evaluator, err := newEvaluator(ctx, cfg, gate)
	if err != nil {
		return err
	}
	ctrls, err := controls.Build(withCooldown(cfg, o.CooldownDays))
	if err != nil {
		return app.UsageError(err.Error(), "Fix the option in the config file. vet config validate checks it.")
	}

	dirs, err := state.PrepareDirs(state.DirRequest{Dirs: rt.Dirs, Ephemeral: o.State.EphemeralFrom(a.LookupEnv)})
	if err != nil {
		return err
	}
	if dirs.Warning != "" {
		tui.Warning("%s", dirs.Warning)
	}
	return withState(ctx, dirs, cfg.Cache.Enabled, func(store *state.Store, cache *state.Cache) error {
		ttl, err := cfg.Cache.TTL.Value()
		if err != nil {
			return app.UsageError("cache.ttl: "+err.Error(), "Set a duration such as 24h or 7d.")
		}
		set, err := enrichers.Build(enrichers.Options{
			APIURL: cfg.Cloud.Endpoints.API, CommunityURL: cfg.Cloud.Endpoints.Community,
			Credentials: creds, Workers: cfg.Scan.Concurrency, TTL: ttl,
		})
		if err != nil {
			return err
		}
		defer closeWarn("the enrichment connections", set.Close)

		within, err := cfg.State.ContinueWithin.Value()
		if err != nil {
			return app.UsageError("state.continue_within: "+err.Error(), "Set a duration such as 24h.")
		}
		exclude := append(append([]string{}, cfg.Scan.Exclude...), o.Exclude...)
		hash, err := state.OptionsHash(hashed{BaseRef: o.BaseRef, Exclude: exclude, API: cfg.Cloud.Endpoints.API, Anonymous: creds.Anonymous()})
		if err != nil {
			return err
		}
		kind, mode := o.Kind, report.ScanModeFull
		if kind == "" {
			kind = report.ScanKindScan
		}
		if o.BaseRef != "" {
			mode = report.ScanModeDelta
		}
		v := view.NewScan(view.Options{Target: o.Target, BaseRef: o.BaseRef, Animate: animate()})
		eo := engine.Options{
			Store: store, Cache: cache, NoCacheRead: o.NoCache, Source: src,
			Extractors: func(plugin.ArtifactKind) ([]plugin.Extractor, error) { return extractors.Default() },
			Enrichers:  enricherSpecs(set), Controls: engineControls(ctrls), Exclude: exclude,
			Kind: kind, Mode: mode, BaseRef: o.BaseRef, OptionsHash: hash, VetVersion: version.Version(),
			Resume: o.Resume, Fresh: o.Fresh, ContinueWithin: within, Strict: o.Strict || cfg.Scan.Strict,
			BatchSize: 100, Observer: v,
			Finalize: func(ctx context.Context, s *state.Scan) (report.Gate, error) { return evaluator.Finalize(ctx, s) },
		}
		res, runErr := engine.Run(ctx, eo)
		if res == nil {
			return runErr
		}
		defer closeWarn("the scan file", res.Scan.Close)
		defer applyRetention(ctx, cfg, store, cache)
		notContinued(res)
		if res.Entry.Status == state.StatusInterrupted {
			tui.Warning("Saved the progress of scan %s. Run vet scan again to continue it.", res.Entry.ID)
		}
		if res.Entry.Status != state.StatusCompleted {
			return runErr
		}
		return errors.Join(Render(ctx, res.Scan, v, outs), strictError(runErr))
	})
}

// CodeStrict is the error code of a scan that --strict fails. The command
// exits with code 3.
const CodeStrict = "scan_strict_diagnostic"

func strictError(err error) error {
	if !errors.Is(err, engine.ErrStrict) {
		return err
	}
	return usefulerror.NewUsefulError().WithCode(CodeStrict).
		WithHumanError("--strict: the scan has a diagnostic").
		WithHelp("The diagnostics above name the cause. Fix it, or scan without --strict to fail open.").
		WithMsg(err.Error())
}

// Render prints the stderr summary of a completed scan, writes the report
// to the destinations, and returns app.ErrGateFailed for a failed gate.
func Render(ctx context.Context, r plugin.Report, v *view.Scan, outs []engine.Output) error {
	var diags []*report.Diagnostic
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		if rec.Diagnostic != nil {
			diags = append(diags, rec.Diagnostic)
		}
	}
	changes, err := view.CountChanges(ctx, r)
	if err != nil {
		return err
	}
	if err := engine.WriteOutputs(ctx, r, outs, output.Stdout()); err != nil {
		return err
	}
	v.Finish(r.Header(), r.Trailer(), diags, changes)
	if r.Trailer().Gate.Outcome == report.GateFail {
		return app.ErrGateFailed
	}
	return nil
}

// Outputs builds the destinations of -o and --report. The options of a
// format come from plugins.<format>.options, then from extra, which holds
// the options that a flag sets.
func Outputs(cfg *config.Config, out string, reports []string, extra map[string]map[string]any) ([]engine.Output, error) {
	reg := sinks.Builtin()
	dests, err := reg.Destinations(out, reports, output.CurrentMode())
	if err != nil {
		return nil, err
	}
	outs := make([]engine.Output, 0, len(dests))
	for _, d := range dests {
		opts := map[string]any{}
		for k, v := range cfg.PluginOptions(d.Format) {
			opts[k] = v
		}
		for k, v := range extra[d.Format] {
			opts[k] = v
		}
		s, err := reg.New(d.Format, plugin.MapConfig(opts))
		if _, ok := usefulerror.AsUsefulError(err); ok {
			return nil, err
		}
		if err != nil {
			return nil, app.UsageError(err.Error(), "Fix the option in the config file.")
		}
		outs = append(outs, engine.Output{Format: d.Format, Path: d.Path, Sink: s})
	}
	return outs, nil
}

func newEvaluator(ctx context.Context, cfg *config.Config, s policy.Settings) (*policy.Evaluator, error) {
	var srcs []plugin.PolicySource
	if s.File != "" {
		srcs = append(srcs, file.New(s.File))
	}
	if cfg.PluginEnabled(tenantpolicy.Name, false) {
		src, err := tenantpolicy.New(plugin.MapConfig(cfg.PluginOptions(tenantpolicy.Name)))
		if err != nil {
			return nil, app.UsageError(fmt.Sprintf("plugins.%s.options: %v", tenantpolicy.Name, err), "Fix the option in the config file.")
		}
		srcs = append(srcs, src)
	}
	return policy.NewFromSources(ctx, s.FailOn, nil, srcs...)
}

func withState(ctx context.Context, dirs *state.Dirs, useCache bool, fn func(*state.Store, *state.Cache) error) (err error) {
	defer func() { err = errors.Join(err, dirs.Close()) }()
	store, err := state.Open(ctx, state.Options{StateDir: dirs.State, CacheDir: dirs.Cache})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	var cache *state.Cache
	if useCache {
		if cache, err = state.OpenCache(ctx, dirs.Cache); err != nil {
			return err
		}
		defer func() { err = errors.Join(err, cache.Close()) }()
	}
	return fn(store, cache)
}

func enricherSpecs(set *enrichers.Set) []engine.Enricher {
	out := make([]engine.Enricher, 0, len(set.Specs))
	for _, s := range set.Specs {
		out = append(out, engine.Enricher{Name: s.Name, Version: s.Version, TTL: s.TTL, Plugin: s.Plugin})
	}
	return out
}

func engineControls(cs []controls.Control) []engine.Control {
	out := make([]engine.Control, 0, len(cs))
	for _, c := range cs {
		out = append(out, engine.Control{ID: c.Name, Plugin: c.Plugin})
	}
	return out
}

// pluginSettings applies the flags that map to a plugin option over the
// config (decisions P7).
type pluginSettings struct {
	cfg       *config.Config
	overrides map[string]map[string]any
}

func withCooldown(cfg *config.Config, days int) pluginSettings {
	s := pluginSettings{cfg: cfg, overrides: map[string]map[string]any{}}
	if days > 0 {
		s.overrides[cooldown.Name] = map[string]any{"days": days}
	}
	return s
}

func (s pluginSettings) PluginEnabled(name string, def bool) bool {
	return s.cfg.PluginEnabled(name, def)
}

func (s pluginSettings) PluginOptions(name string) map[string]any {
	out := map[string]any{}
	for k, v := range s.cfg.PluginOptions(name) {
		out[k] = v
	}
	for k, v := range s.overrides[name] {
		out[k] = v
	}
	return out
}

var reasonText = map[state.Reason]string{
	state.ReasonFresh:          "--fresh is set",
	state.ReasonOptionsChanged: "the scan options changed",
	state.ReasonVersionChanged: "the vet version changed",
	state.ReasonTooOld:         "it stopped more than state.continue_within ago. --resume continues it",
	state.ReasonLive:           "another vet process runs it",
}

func notContinued(res *engine.Result) {
	switch {
	case res.Continued:
		tui.Info("Continued the stopped scan %s.", res.Entry.ID)
	case res.NotContinued != nil && res.NotContinued.Stopped != nil:
		tui.Info("Started a new scan. vet did not continue scan %s, because %s.",
			res.NotContinued.Stopped.ID, reasonText[res.NotContinued.Reason])
	}
}

// RetentionOf returns the retention rules of the config.
func RetentionOf(cfg *config.Config) (state.Retention, error) {
	r := cfg.State.Retention
	interrupted, err := r.Interrupted.Value()
	if err != nil {
		return state.Retention{}, app.UsageError("state.retention.interrupted: "+err.Error(), "Set a duration such as 7d.")
	}
	size, err := r.MaxSize.Bytes()
	if err != nil {
		return state.Retention{}, app.UsageError("state.retention.max_size: "+err.Error(), "Set a size such as 2GB.")
	}
	return state.Retention{PerTarget: r.PerTarget, Interrupted: interrupted, MaxSize: size}, nil
}

// applyRetention deletes the old scans and the expired cache entries at the
// end of a scan. It says nothing unless -v is set (scan state design,
// section 6). A failure is a warning, because the scan is complete.
func applyRetention(ctx context.Context, cfg *config.Config, store *state.Store, cache *state.Cache) {
	r, err := RetentionOf(cfg)
	if err != nil {
		tui.Warning("retention: %v", err)
		return
	}
	deleted, err := store.ApplyRetention(ctx, r, time.Now())
	if err != nil {
		tui.Warning("retention: %v", err)
	}
	for _, e := range deleted {
		tui.Faint("Retention deleted scan %s of %s.", e.ID, e.TargetKey)
	}
	if cache == nil {
		return
	}
	n, err := cache.Prune(ctx)
	if err != nil {
		tui.Warning("retention: %v", err)
		return
	}
	if n > 0 {
		tui.Faint("Retention deleted %d expired cache entries.", n)
	}
}

func animate() bool {
	return output.CurrentMode() == output.Rich && term.IsTerminal(int(os.Stderr.Fd()))
}

func closeWarn(what string, fn func() error) {
	if err := fn(); err != nil {
		tui.Warning("close %s: %v", what, err)
	}
}

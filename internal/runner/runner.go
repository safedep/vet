// Package runner wires a scan from the config of a run: the state, the
// source, the extractors, the enrichers, the controls, the policy, the
// views and the report destinations. The scan and endpoint commands share
// it, because command packages do not import each other.
package runner

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/internal/plugins/cloud/tenantpolicy"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/controls/cooldown"
	"github.com/safedep/vet/v2/internal/plugins/enrichers"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/actionrefs"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/insights"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/plugins/sources/git"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/banner"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/version"
	"github.com/safedep/vet/v2/internal/view"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Options are the inputs of a scan, from the flags of the command.
type Options struct {
	Target string
	// Source replaces the source that vet builds from Target, for example
	// the endpoint source of vet endpoint audit.
	Source  plugin.Source
	Kind    report.ScanKind
	BaseRef string

	FailOn  string
	Policy  string
	Reports []string
	// Packages is the --packages value, or empty.
	Packages string

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

// RegisterFlags registers the flags that every scan command takes: the
// gate, the reports, the state and the cooldown window.
func (o *Options) RegisterFlags(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&o.FailOn, "fail-on", "", "Exit 1 on a finding at this severity or above, or on an attack with attacks")
	f.StringVar(&o.Policy, "policy", "", "Policy v2 file, directory or name")
	f.StringArrayVar(&o.Reports, "report", nil, "Also write the report as FORMAT=PATH. Repeatable")
	f.BoolVar(&o.Strict, "strict", false, "Exit 3 when the report has a diagnostic")
	f.BoolVar(&o.Resume, "resume", false, "Continue the stopped scan, however old it is")
	f.BoolVar(&o.Fresh, "fresh", false, "Start a new scan in place of a stopped one")
	f.BoolVar(&o.NoCache, "no-cache", false, "Ignore and refresh the cached enrichments")
	f.IntVar(&o.CooldownDays, "cooldown-days", 0, "Days of the dependency cooldown window")
	o.State.Register(f)
	c.MarkFlagsMutuallyExclusive("resume", "fresh")
}

// packagesOf returns the --packages value, else scan.packages, or empty for
// the default of each artifact kind.
func packagesOf(o Options, cfg *config.Config) (model.Packages, error) {
	p := model.Packages(cmp.Or(o.Packages, cfg.Scan.Packages))
	if p != "" && !slices.Contains(model.PackagesValues, p) {
		return "", app.UsageError(fmt.Sprintf("--packages %q is not valid", p), "Use declared, installed or all.")
	}
	if o.BaseRef != "" && p.Installed() {
		return "", app.UsageError("--base-ref reads declared packages only, because git does not hold installed packages",
			"Remove --base-ref, or scan with --packages declared.")
	}
	return p, nil
}

// packagesFor returns where vet finds the packages of an artifact. An image
// holds installed packages, so it reads both by default. The selection
// applies to directories and images only.
func packagesFor(p model.Packages, k plugin.ArtifactKind) model.Packages {
	switch {
	case k != plugin.ArtifactDirectory && k != plugin.ArtifactImage:
		return model.PackagesDeclared
	case p != "":
		return p
	case k == plugin.ArtifactImage:
		return model.PackagesAll
	}
	return model.PackagesDeclared
}

// lockableKeys are the config keys of the scan flags that the user set. A
// managed file with lockdown refuses each of them.
func (o Options) lockableKeys() []string {
	keys := gateKeys(o.FailOn, o.Policy)
	if o.Strict {
		keys = append(keys, "scan.strict")
	}
	if len(o.Exclude) > 0 {
		keys = append(keys, "scan.exclude")
	}
	if o.Packages != "" {
		keys = append(keys, "scan.packages")
	}
	if o.CooldownDays > 0 {
		keys = append(keys, "plugins."+cooldown.Name+".options.days")
	}
	return keys
}

// gateKeys are the config keys of --fail-on and --policy, when set.
func gateKeys(failOn, policyFile string) []string {
	var keys []string
	if failOn != "" {
		keys = append(keys, "policy.fail_on")
	}
	if policyFile != "" {
		keys = append(keys, "policy.file")
	}
	return keys
}

// hashed are the options that change what a scan stores. A stopped scan
// continues only when they are the same.
type hashed struct {
	BaseRef   string   `json:"base_ref,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
	API       string   `json:"api"`
	Anonymous bool     `json:"anonymous"`
	Tenant    string   `json:"tenant,omitempty"`
	Enrichers []string `json:"enrichers,omitempty"`
	Packages  string   `json:"packages,omitempty"`
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
	if err := rt.RefuseLocked(o.lockableKeys()...); err != nil {
		return err
	}

	gate, err := policy.ResolveSettings(o.FailOn, o.Policy, cfg.Policy)
	if err != nil {
		return err
	}
	outs, err := Outputs(cfg, a.Globals.Output, o.Reports, nil)
	if err != nil {
		return err
	}
	packages, err := packagesOf(o, cfg)
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
	src := o.Source
	if src == nil {
		if src, err = sources.New(o.Target, sources.Options{Tokens: github.DefaultProvider()}); err != nil {
			return err
		}
	}
	pol, err := policySource(ctx, o.Target, o.BaseRef, gate.File, rt)
	if err != nil {
		return err
	}
	evaluator, err := newEvaluator(ctx, cfg, gate.FailOn, pol.Source)
	if err != nil {
		return err
	}
	configError := func(err error) error {
		return app.UsageError(err.Error(), "Fix the option in the config file. vet config validate checks it.")
	}
	ctrls, err := controls.Build(withCooldown(cfg, o.CooldownDays))
	if err != nil {
		return configError(err)
	}
	refs, err := actionRefs(cfg)
	if err != nil {
		return configError(err)
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
			CodeUsageDir: codeUsageDir(cfg, o),
			CodeUsage:    codeusage.Options{BaseRef: o.BaseRef},
			ActionRefs:   refs,
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
		hash, err := state.OptionsHash(hashed{
			BaseRef: o.BaseRef, Exclude: exclude, API: cfg.Cloud.Endpoints.API, Anonymous: creds.Anonymous(),
			Tenant: creds.TenantDomain(), Enrichers: enricherIDs(set), Packages: string(packages),
		})
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
		banner.Print(version.Version())
		v := view.NewScan(view.Options{Target: git.Redact(o.Target), BaseRef: o.BaseRef, Kind: kind, Animate: animate()})
		eo := engine.Options{
			Store: store, Cache: cache, NoCacheRead: o.NoCache, Source: src,
			Extractors: func(k plugin.ArtifactKind) ([]plugin.Extractor, error) {
				return extractors.For(packagesFor(packages, k))
			},
			Enrichers: enricherSpecs(set), Controls: engineControls(ctrls), Exclude: exclude,
			Kind: kind, Mode: mode, BaseRef: o.BaseRef, OptionsHash: hash, VetVersion: version.Version(),
			Resume: o.Resume, Fresh: o.Fresh, ContinueWithin: within, Strict: o.Strict || cfg.Scan.Strict,
			Diagnostics: pol.diagnostics(),
			BatchSize:   100, Observer: v, Opened: notContinued,
			Finalize: func(ctx context.Context, s *state.Scan) (report.Gate, error) {
				if err := syncInventory(ctx, cfg, store, s); err != nil {
					return report.Gate{}, err
				}
				g, err := evaluator.Finalize(ctx, s)
				g.PolicyChanged = pol.Changed
				return g, err
			},
		}
		res, runErr := engine.Run(ctx, eo)
		v.Stop()
		if res == nil {
			return runErr
		}
		defer closeWarn("the scan file", res.Scan.Close)
		defer applyRetention(ctx, cfg, store, cache)
		if res.Entry.Status == state.StatusInterrupted {
			tui.Warning("Saved the progress of scan %s. Run vet scan again to continue it.", res.Entry.ID)
		}
		if res.Entry.Status != state.StatusCompleted {
			return runErr
		}
		renderErr := Render(ctx, res.Scan, v, outs)
		if res.Installed != "" && packages == "" && o.BaseRef == "" {
			tui.Info("The installed packages in %s are not in the scan. Scan with --packages all to check them too.", res.Installed)
		}
		return outcome(renderErr, runErr)
	})
}

// outcome joins the error of the report and the error of the scan. A gate
// on a scan with a --strict diagnostic ran on incomplete data, so the
// strict error wins and exits with code 3. Render already printed the gate.
func outcome(renderErr, runErr error) error {
	strict := strictError(runErr)
	if strict != nil && errors.Is(renderErr, app.ErrGateFailed) {
		renderErr = nil
	}
	return errors.Join(renderErr, strict)
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
	s, err := overview.Read(ctx, r)
	if err != nil {
		return err
	}
	var files []string
	for _, o := range outs {
		if o.Path != "" {
			files = append(files, o.Path)
		}
	}
	v.Report(files)
	if err := engine.WriteOutputs(ctx, r, outs, output.Stdout()); err != nil {
		return err
	}
	publish(ctx, r, outs)
	v.Finish(r.Header(), r.Trailer(), s)
	if r.Trailer().Gate.Outcome == report.GateFail {
		return app.ErrGateFailed
	}
	return nil
}

// publish runs each sink that publishes the report itself. A failure is a
// warning: it never changes the exit code, which the gate sets.
func publish(ctx context.Context, r plugin.Report, outs []engine.Output) {
	for _, o := range outs {
		p, ok := o.Sink.(plugin.Publisher)
		if !o.Publish || !ok {
			continue
		}
		where, err := p.Publish(ctx, r)
		if where != "" {
			tui.Info("vet published the %s report to %s", o.Format, where)
		}
		if err != nil {
			tui.Warning("--report %s: %v", o.Format, err)
		}
	}
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
		outs = append(outs, engine.Output{Format: d.Format, Path: d.Path, Publish: d.Publish, Sink: s})
	}
	return outs, nil
}

// codeUsageDir returns the directory of a scan of a local directory when
// plugins.codeusage is on, else "".
func codeUsageDir(cfg *config.Config, o Options) string {
	if o.Source != nil || !cfg.PluginEnabled(codeusage.Name, false) {
		return ""
	}
	info, err := os.Stat(o.Target)
	if err != nil || !info.IsDir() {
		return ""
	}
	dir, err := filepath.Abs(o.Target)
	if err != nil {
		return ""
	}
	return dir
}

// actionRefs builds the actionrefs enricher, or nil when the config turns
// it off.
func actionRefs(cfg *config.Config) (*actionrefs.Enricher, error) {
	if !cfg.PluginEnabled(actionrefs.Name, true) {
		return nil, nil
	}
	return actionrefs.New(plugin.MapConfig(cfg.PluginOptions(actionrefs.Name)), github.DefaultProvider(), cfg.GitHub.APIURL)
}

// CodeInventorySync is the diagnostic code of an inventory sync that did
// not reach SafeDep Cloud.
const CodeInventorySync = "inventory_sync_unavailable"

// syncInventory sends the inventory of an endpoint audit when
// plugins.cloud-inventory is on. A sync that does not reach SafeDep Cloud
// is a diagnostic: the batch waits in the log of the state directory.
func syncInventory(ctx context.Context, cfg *config.Config, store *state.Store, s *state.Scan) error {
	h := s.Header()
	if h == nil || h.Scan.Kind != report.ScanKindEndpoint || !cfg.PluginEnabled(inventory.Name, false) {
		return nil
	}
	syncer, err := inventory.New(plugin.MapConfig(cfg.PluginOptions(inventory.Name)), inventory.NewWAL(store.StateDir()))
	if err != nil {
		return app.UsageError(fmt.Sprintf("plugins.%s.options: %v", inventory.Name, err), "Fix the option in the config file.")
	}
	var items []report.InventoryItem
	for rec, err := range s.Records(ctx) {
		if err != nil {
			return err
		}
		if rec.Inventory != nil {
			items = append(items, *rec.Inventory)
		}
	}
	err = syncer.Sync(ctx, h.Scan.TargetKey, items)
	if !errors.Is(err, plugin.ErrUnavailable) {
		return err
	}
	return s.AddDiagnostic(ctx, &report.Diagnostic{
		Level: report.DiagnosticWarning, Code: CodeInventorySync, Component: inventory.Name,
		Message: fmt.Sprintf("%s. vet keeps the inventory in %s and sends it on the next scan.", strings.TrimSuffix(err.Error(), ": "+plugin.ErrUnavailable.Error()), inventory.WALFile),
		Count:   1,
	})
}

// newEvaluator builds the evaluator of the --fail-on value, the policy
// file source, when not nil, and the tenant policy.
func newEvaluator(ctx context.Context, cfg *config.Config, failOn report.FailOn, policyFile plugin.PolicySource) (*policy.Evaluator, error) {
	var srcs []plugin.PolicySource
	if policyFile != nil {
		srcs = append(srcs, policyFile)
	}
	if cfg.PluginEnabled(tenantpolicy.Name, false) {
		src, err := tenantpolicy.New(plugin.MapConfig(cfg.PluginOptions(tenantpolicy.Name)))
		if err != nil {
			return nil, app.UsageError(fmt.Sprintf("plugins.%s.options: %v", tenantpolicy.Name, err), "Fix the option in the config file.")
		}
		srcs = append(srcs, src)
	}
	attacks, err := controls.AttackIDs()
	if err != nil {
		return nil, err
	}
	return policy.NewFromSources(ctx, policy.Options{FailOn: failOn, Attacks: attacks}, srcs...)
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

// enricherIDs names each enabled enricher with its version. A stopped scan
// with another set has rows that this run would not write.
func enricherIDs(set *enrichers.Set) []string {
	out := make([]string, 0, len(set.Specs))
	for _, s := range set.Specs {
		out = append(out, s.Name+"@"+s.Version)
	}
	return out
}

func enricherSpecs(set *enrichers.Set) []engine.Enricher {
	out := make([]engine.Enricher, 0, len(set.Specs))
	for _, s := range set.Specs {
		out = append(out, engine.Enricher{
			Name: s.Name, Version: s.Version, TTL: s.TTL, Plugin: s.Plugin,
			Prior: s.Name == insights.Name, Local: s.Local, SkipEmpty: s.SkipEmpty,
		})
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
	state.ReasonFileMissing:    "its scan file is missing",
	state.ReasonTooOld:         "it stopped more than state.continue_within ago. --resume continues it",
	state.ReasonLive:           "another vet process runs it",
}

func notContinued(res *engine.Result) {
	switch {
	case res.Continued:
		tui.Info("vet continued scan %s from where it stopped.", res.Entry.ID)
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
// section 6). A failure is a warning, because the scan is complete. A
// signal skips it: the user asked vet to stop, and the next scan applies it.
func applyRetention(ctx context.Context, cfg *config.Config, store *state.Store, cache *state.Cache) {
	if ctx.Err() != nil {
		return
	}
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
		tui.Faint("Retention deleted scan %s of %s", e.ID, e.TargetKey)
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

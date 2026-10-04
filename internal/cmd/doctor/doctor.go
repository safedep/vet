// Package doctor holds the "vet doctor" command.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	gh "github.com/google/go-github/v70/github"
	"github.com/safedep/dry/localdb"
	"github.com/spf13/cobra"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/plugins/enrichers"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/banner"
	"github.com/safedep/vet/v2/internal/tui/checklist"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/version"
)

// Status is the result of a check.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

func (s Status) item() checklist.Status {
	switch s {
	case Fail:
		return checklist.Fail
	case Warn:
		return checklist.Warn
	default:
		return checklist.Pass
	}
}

// Check is one check of "vet doctor". The id is stable.
type Check struct {
	ID      string `json:"id"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

const probeTimeout = 5 * time.Second

// New returns the "vet doctor" command.
func New(a *app.App) *cobra.Command {
	var fix bool
	var f state.Flags
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check the state, the config, the credentials and the endpoints",
		Long: `Check that vet can work: the version, the state directory, its file system
and its scans, the config file, the SafeDep credentials, and the SafeDep
Insights and Threat Intel endpoints. Each check has a stable id, a status (pass, warn or
fail), a message and a fix. vet exits 1 when a check fails.

--fix repairs the state: it marks a scan whose process stopped as
interrupted, adds index entries for scan files that have none, removes
entries whose file is gone, sets the directory mode to 0700 and applies
the retention rules over the size limit. It never deletes a completed
scan.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			checks := run(cmd.Context(), a, f, fix)
			p, err := a.Printer()
			if err != nil {
				return err
			}
			items := make([]checklist.Item, 0, len(checks))
			failed := false
			for _, c := range checks {
				items = append(items, checklist.Item{Status: c.Status.item(), Name: c.ID, Text: escape.Line(c.Message), Fix: escape.Line(c.Fix)})
				failed = failed || c.Status == Fail
			}
			if err := p.PrintText(checks, checklist.Lines(items)...); err != nil {
				return err
			}
			if failed {
				tui.Error("A check failed.")
				return app.ErrCheckFailed
			}
			return nil
		},
	}
	c.Flags().BoolVar(&fix, "fix", false, "Repair the state")
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	c.Flags().StringVar(&f.CacheDir, "cache-dir", "", "Directory of the enrichment cache")
	return c
}

func run(ctx context.Context, a *app.App, f state.Flags, fix bool) []Check {
	checks := []Check{{ID: "vet.version", Status: Pass, Message: "vet " + banner.DisplayVersion(version.Version())}}
	rt, err := a.Config(app.ConfigOptions{StateDir: f.StateDir, CacheDir: f.CacheDir})
	if err != nil {
		return append(checks, Check{ID: "config.load", Status: Fail, Message: err.Error(), Fix: "vet config validate"})
	}
	checks = append(checks, configCheck(rt.Loaded))
	checks = append(checks, latestRelease(ctx, rt.Config))
	checks = append(checks, installChecks(rt.Config)...)
	checks = append(checks, stateChecks(ctx, rt, fix)...)
	creds, credCheck := credentialCheck(rt.Config)
	checks = append(checks, credCheck)
	if creds != nil {
		checks = append(checks, endpointChecks(ctx, rt.Config, creds)...)
	}
	return checks
}

func configCheck(l *config.Loaded) Check {
	c := Check{ID: "config.file", Status: Pass, Message: "no config file, the defaults apply"}
	if l.File != "" {
		c.Message = l.File + " is valid"
	}
	if len(l.UnknownKeys) > 0 {
		c.Status, c.Message, c.Fix = Warn, fmt.Sprintf("%s has unknown keys: %s", l.File, strings.Join(l.UnknownKeys, ", ")), "vet config validate"
	}
	return c
}

func latestRelease(ctx context.Context, cfg *config.Config) Check {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	client, err := github.NewClient(ctx, nil, cfg.GitHub.APIURL, &http.Client{Timeout: probeTimeout})
	if err != nil {
		return Check{ID: "vet.release", Status: Warn, Message: "vet could not check the latest release: " + err.Error()}
	}
	releases, _, err := client.Repositories.ListReleases(ctx, "safedep", "vet", &gh.ListOptions{PerPage: 100})
	if err != nil {
		return Check{ID: "vet.release", Status: Warn, Message: "vet could not check the latest release: " + err.Error()}
	}
	var tags []string
	for _, r := range releases {
		if !r.GetDraft() {
			tags = append(tags, r.GetTagName())
		}
	}
	return releaseCheck(tags, version.Version())
}

// releaseCheck compares this vet with the newest release of its major
// version. A pre-release build compares with the pre-releases too, so an
// alpha build of v2 learns about a newer alpha and never about v1. A build
// with no version or a pseudo-version is a development build, and passes.
func releaseCheck(tags []string, current string) Check {
	shown := banner.DisplayVersion(current)
	cur := semverOf(current)
	if cur == "" || module.IsPseudoVersion(cur) {
		return Check{ID: "vet.release", Status: Pass, Message: "vet " + shown + " is a development build"}
	}
	newest := newestRelease(tags, cur)
	if newest == "" {
		return Check{ID: "vet.release", Status: Pass, Message: "vet " + shown + " has no newer release"}
	}
	switch c := semver.Compare(semverOf(newest), cur); {
	case c > 0:
		return Check{ID: "vet.release", Status: Warn, Message: "the newest release is " + newest + ", this is " + shown, Fix: "Upgrade vet."}
	case c < 0:
		return Check{ID: "vet.release", Status: Pass, Message: "vet " + shown + " is newer than the newest release " + newest}
	}
	return Check{ID: "vet.release", Status: Pass, Message: "vet " + shown + " is the newest release"}
}

// newestRelease returns the newest tag of the major version of cur. It
// takes a pre-release only when cur is a pre-release.
func newestRelease(tags []string, cur string) string {
	var newest, newestSemver string
	for _, tag := range tags {
		v := semverOf(tag)
		if v == "" || semver.Major(v) != semver.Major(cur) || semver.Prerelease(v) != "" && semver.Prerelease(cur) == "" {
			continue
		}
		if newest == "" || semver.Compare(v, newestSemver) > 0 {
			newest, newestSemver = tag, v
		}
	}
	return newest
}

// semverOf returns the version in the form of golang.org/x/mod/semver, with
// the leading v, or "" for a version that is not valid. A release build
// sets the version with no v.
func semverOf(v string) string {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

func stateChecks(ctx context.Context, rt *config.Runtime, fix bool) []Check {
	dir := rt.Dirs.State
	var out []Check
	if err := appdir.Ensure(dir); err != nil {
		return append(out, Check{ID: "state.dir", Status: Fail, Message: err.Error(), Fix: "Set --state-dir to a writable directory, or use --ephemeral."})
	}
	out = append(out, Check{ID: "state.dir", Status: Pass, Message: dir + " is writable"})
	if err := localdb.CheckLocalFilesystem(dir); err != nil {
		return append(out, Check{ID: "state.filesystem", Status: Fail, Message: err.Error(), Fix: "Set --state-dir to a local directory, or use --ephemeral."})
	}
	out = append(out, Check{ID: "state.filesystem", Status: Pass, Message: dir + " is on a local file system"})

	s, err := state.Open(ctx, state.Options{StateDir: dir, CacheDir: rt.Dirs.Cache})
	if err != nil {
		return append(out, Check{ID: "state.index", Status: Fail, Message: err.Error(), Fix: "Check that the state directory is writable."})
	}
	defer func() {
		if err := s.Close(); err != nil {
			tui.Warning("close the scan index: %v", err)
		}
	}()
	out = append(out, Check{ID: "state.index", Status: Pass, Message: "the scan index opens"})

	mode := Check{ID: "state.mode", Status: Pass, Message: dir + " has mode 0700"}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o077 != 0 && !windows() {
		if fix {
			if err := os.Chmod(dir, 0o700); err != nil {
				mode = Check{ID: "state.mode", Status: Fail, Message: err.Error()}
			}
		} else {
			mode = Check{ID: "state.mode", Status: Warn, Message: fmt.Sprintf("%s has mode %#o", dir, info.Mode().Perm()), Fix: "vet doctor --fix"}
		}
	}
	out = append(out, mode)

	issues, err := s.Inspect(ctx)
	if err != nil {
		return append(out, Check{ID: "state.scans", Status: Fail, Message: err.Error()})
	}
	if fix && !issues.Empty() {
		if err := s.Repair(ctx, issues); err != nil {
			return append(out, Check{ID: "state.scans", Status: Fail, Message: err.Error()})
		}
		tui.Success("Repaired the state.")
		issues = &state.Issues{}
	}
	scans := Check{ID: "state.scans", Status: Pass, Message: "every scan has its file and its index entry"}
	var problems []string
	for _, e := range issues.StaleRunning {
		problems = append(problems, fmt.Sprintf("scan %s is marked running, but its process stopped", e.ID))
	}
	for _, e := range issues.MissingFiles {
		problems = append(problems, fmt.Sprintf("scan %s has no scan file", e.ID))
	}
	if n := len(issues.Orphans); n > 0 {
		problems = append(problems, fmt.Sprintf("%d scan files have no index entry", n))
	}
	if len(problems) > 0 {
		scans = Check{ID: "state.scans", Status: Warn, Message: strings.Join(problems, "; "), Fix: "vet doctor --fix"}
	}
	out = append(out, scans)
	return append(out, sizeCheck(ctx, rt.Config, s, fix))
}

func sizeCheck(ctx context.Context, cfg *config.Config, s *state.Store, fix bool) Check {
	r, err := runner.RetentionOf(cfg)
	if err != nil {
		return Check{ID: "state.size", Status: Fail, Message: err.Error(), Fix: "vet config validate"}
	}
	u, err := s.Usage(ctx)
	if err != nil {
		return Check{ID: "state.size", Status: Fail, Message: err.Error()}
	}
	limit := ""
	if r.MaxSize > 0 {
		limit = string(cfg.State.Retention.MaxSize)
	}
	if r.MaxSize > 0 && u.Bytes > r.MaxSize {
		if !fix {
			return Check{ID: "state.size", Status: Warn, Message: fmt.Sprintf("the scans use %s, over the limit of %s", humanize.Bytes(u.Bytes), limit), Fix: "vet doctor --fix"}
		}
		if _, err := s.ApplyRetention(ctx, r, time.Now()); err != nil {
			return Check{ID: "state.size", Status: Fail, Message: err.Error()}
		}
	}
	return Check{ID: "state.size", Status: Pass, Message: sizeMessage(u.Scans, u.Bytes, limit)}
}

// sizeMessage names the limit as the config sets it, as vet state show
// does.
func sizeMessage(scans int, used int64, limit string) string {
	msg := fmt.Sprintf("%d scans use %s", scans, humanize.Bytes(used))
	if limit != "" {
		msg += " of the limit of " + limit
	}
	return msg
}

func credentialCheck(cfg *config.Config) (*credentials.Result, Check) {
	res, err := credentials.Resolve(credentials.FromConfig(cfg.Cloud.Profile, cfg.Cloud.InsecureKeychainFallback, cfg.Cloud.KeychainFile))
	if err != nil {
		return nil, Check{ID: "credentials", Status: Fail, Message: err.Error(), Fix: "Set both SAFEDEP_API_KEY and SAFEDEP_TENANT_ID, or neither, or run vet auth login."}
	}
	c := Check{ID: "credentials", Status: Pass}
	switch {
	case res.Anonymous():
		c.Message = "no credentials: vet uses the community endpoints"
	default:
		c.Message = fmt.Sprintf("tenant %s from the %s, profile %s", res.TenantDomain(), res.Source(), res.Profile)
	}
	if res.Warning != "" {
		c.Status, c.Message = Warn, res.Warning
	}
	return res, c
}

func endpointChecks(ctx context.Context, cfg *config.Config, creds *credentials.Result) []Check {
	set, err := enrichers.Build(enrichers.Options{
		APIURL: cfg.Cloud.Endpoints.API, CommunityURL: cfg.Cloud.Endpoints.Community, Credentials: creds, Workers: 1,
	})
	if err != nil {
		return []Check{{ID: "endpoint", Status: Fail, Message: err.Error()}}
	}
	defer func() {
		if err := set.Close(); err != nil {
			tui.Warning("close the endpoint connections: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	results := set.Probe(ctx)
	var out []Check
	for _, sp := range set.Specs {
		c := Check{ID: "endpoint." + sp.Name, Status: Pass, Message: sp.Name + " answers"}
		if err := results[sp.Name]; err != nil {
			c = Check{ID: "endpoint." + sp.Name, Status: Fail, Message: sp.Name + " did not answer: " + err.Error(), Fix: "Check the network and HTTPS_PROXY."}
			if errors.Is(err, context.DeadlineExceeded) {
				c.Message = fmt.Sprintf("%s did not answer in %s", sp.Name, probeTimeout)
			}
		}
		out = append(out, c)
	}
	return out
}

func windows() bool { return os.PathSeparator == '\\' }

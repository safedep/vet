package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

const lock = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/evil": {"version": "1.0.0"}
  }
}`

func project(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "vendor"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vendor", "requirements.txt"), []byte("flask==3.0.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o600))
	return dir
}

// fakeEnricher sets a license on each package, and counts the packages.
type fakeEnricher struct {
	mu    sync.Mutex
	seen  int
	err   error
	delay time.Duration
}

func (f *fakeEnricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen += len(pkgs)
	if f.err != nil {
		return f.err
	}
	for _, p := range pkgs {
		p.Insight = &model.Insight{Licenses: []string{"MIT"}}
	}
	return nil
}

// nameControl reports each package with a name.
type nameControl struct {
	name string
	err  error
}

func (c nameControl) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	if c.err != nil {
		return nil, c.err
	}
	var out []finding.Finding
	for _, p := range m.Packages {
		if p.ID.Name == c.name {
			out = append(out, finding.ForPackage(finding.Meta{
				ControlID: "test-name", Family: finding.FamilyMalware, Severity: finding.SeverityCritical, Title: "bad name",
			}, m.Path, p, finding.Key{}))
		}
	}
	return out, nil
}

type fixture struct {
	store *state.Store
	cache *state.Cache
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	s, err := state.Open(context.Background(), state.Options{StateDir: filepath.Join(root, "state")})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	c, err := state.OpenCache(context.Background(), filepath.Join(root, "cache"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, c.Close()) })
	return &fixture{store: s, cache: c}
}

func codeExtractors(plugin.ArtifactKind) ([]plugin.Extractor, error) { return extractors.Default() }

func (f *fixture) options(t *testing.T, target string, en *fakeEnricher, controls ...Control) Options {
	t.Helper()
	src, err := sources.New(target, sources.Options{})
	require.NoError(t, err)
	o := Options{
		Store: f.store, Cache: f.cache, Source: src, Extractors: codeExtractors,
		OptionsHash: "h", VetVersion: "test", BatchSize: 2, Controls: controls,
	}
	if en != nil {
		o.Enrichers = []Enricher{{Name: "fake", Version: "1", TTL: time.Hour, Plugin: en}}
	}
	return o
}

func runScan(t *testing.T, o Options) *Result {
	t.Helper()
	res, err := Run(context.Background(), o)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, res.Scan.Close()) })
	return res
}

func TestRunFullScan(t *testing.T) {
	f := newFixture(t)
	en := &fakeEnricher{}
	o := f.options(t, project(t), en, Control{ID: "test-name", Plugin: nameControl{name: "evil"}})
	o.Exclude = []string{"vendor"}
	res := runScan(t, o)

	assert.Equal(t, state.StatusCompleted, res.Entry.Status)
	assert.Equal(t, 3, en.seen, "left-pad, evil and requests once each, and flask is excluded")
	assert.Equal(t, 1, res.Entry.Findings)
	assert.Equal(t, string(report.GateNone), res.Entry.Gate)

	tr := res.Scan.Trailer()
	require.NotNil(t, tr)
	assert.Equal(t, 1, tr.Summary.Findings)
	assert.Equal(t, 3, tr.Summary.Packages)
	assert.Equal(t, 2, tr.Summary.Manifests)

	p, err := res.Scan.Package(context.Background(), model.PackageID{Ecosystem: model.EcosystemNpm, Name: "left-pad", Version: "1.3.0"})
	require.NoError(t, err)
	require.NotNil(t, p.Insight)
	assert.True(t, p.Direct)

	h := res.Scan.Header()
	require.NotNil(t, h)
	assert.Equal(t, res.Entry.ID, h.Scan.ID)
	assert.False(t, h.Scan.Continued)
}

func TestCacheAnswersTheNextScan(t *testing.T) {
	f := newFixture(t)
	dir := project(t)
	runScan(t, f.options(t, dir, &fakeEnricher{}))

	en := &fakeEnricher{}
	o := f.options(t, dir, en)
	o.Fresh = true
	res := runScan(t, o)
	assert.Zero(t, en.seen, "the cache answers each package")
	p, err := res.Scan.Package(context.Background(), model.PackageID{Ecosystem: model.EcosystemPyPI, Name: "requests", Version: "2.31.0"})
	require.NoError(t, err)
	require.NotNil(t, p.Insight)
}

func TestFailOpen(t *testing.T) {
	cases := []struct {
		name      string
		enrichErr error
		control   error
		strict    bool
		wantErr   error
		wantCode  string
		wantLevel report.DiagnosticLevel
	}{
		{name: "enricher unavailable", enrichErr: plugin.ErrUnavailable, wantCode: CodeEnrichUnavailable, wantLevel: report.DiagnosticWarning},
		{name: "enricher unavailable strict", enrichErr: plugin.ErrUnavailable, strict: true, wantCode: CodeEnrichUnavailable, wantLevel: report.DiagnosticWarning},
		{name: "enricher error", enrichErr: errors.New("boom"), wantCode: CodeEnrichFailed, wantLevel: report.DiagnosticError},
		{name: "enricher error strict", enrichErr: errors.New("boom"), strict: true, wantErr: ErrStrict, wantCode: CodeEnrichFailed, wantLevel: report.DiagnosticError},
		{name: "control error", control: errors.New("bad"), wantCode: CodeControlFailed, wantLevel: report.DiagnosticError},
		{name: "control unavailable", control: plugin.ErrUnavailable, wantCode: CodeControlUnavailable, wantLevel: report.DiagnosticWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			o := f.options(t, project(t), &fakeEnricher{err: tc.enrichErr}, Control{ID: "c", Plugin: nameControl{err: tc.control}})
			o.Strict = tc.strict
			res, err := Run(context.Background(), o)
			require.NotNil(t, res)
			t.Cleanup(func() { assert.NoError(t, res.Scan.Close()) })
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, state.StatusCompleted, res.Entry.Status, "the scan completes")

			var diags []*report.Diagnostic
			for rec, err := range res.Scan.Records(context.Background()) {
				require.NoError(t, err)
				if rec.Diagnostic != nil {
					diags = append(diags, rec.Diagnostic)
				}
			}
			require.NotEmpty(t, diags)
			if tc.control == nil {
				require.Len(t, diags, 1, "one diagnostic for a repeated problem")
				assert.Greater(t, diags[0].Count, 1)
			}
			for _, d := range diags {
				assert.Equal(t, tc.wantCode, d.Code)
				assert.Equal(t, tc.wantLevel, d.Level)
			}
		})
	}
}

func TestPURLTarget(t *testing.T) {
	f := newFixture(t)
	en := &fakeEnricher{}
	res := runScan(t, f.options(t, "pkg:npm/evil@1.0.0", en, Control{ID: "test-name", Plugin: nameControl{name: "evil"}}))
	assert.Equal(t, 1, en.seen)
	assert.Equal(t, 1, res.Entry.Findings)
	assert.Equal(t, "purl:pkg:npm/evil@1.0.0", res.Entry.TargetKey)
}

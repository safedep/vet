// Package engine runs a scan: it reads the artifacts of a source, extracts
// the manifests, enriches the packages, evaluates the controls and writes
// the report trailer. The engine owns every write to the scan file. It
// commits each result with the done mark of its unit, so a scan that stops
// can continue (scan state design, section 9).
package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Stage names of a scan.
const (
	StageExtract  = "extract"
	StageEnrich   = "enrich"
	StageEvaluate = "evaluate"
	StageReport   = "report"
)

// Observer receives the progress of a scan. The command renders it.
type Observer interface {
	// Stage starts a stage. index counts from 1.
	Stage(name string, index, total int)
	// Progress reports the units done in the current stage.
	Progress(stage string, done, total int)
}

// NopObserver drops the progress.
type NopObserver struct{}

func (NopObserver) Stage(string, int, int)    {}
func (NopObserver) Progress(string, int, int) {}

// Enricher is one enricher of a scan.
type Enricher struct {
	Name    string
	Version string
	// TTL is how long the cache keeps a result. Zero turns the cache off
	// for the enricher.
	TTL    time.Duration
	Plugin plugin.Enricher
	// Prior also runs the enricher on the previous version of each upgraded
	// or downgraded package, in pull request mode. The result becomes
	// Package.PreviousInsight.
	Prior bool
	// Local is an enricher that reads the target and calls no registry, so
	// it also gets the packages with no version and the local packages.
	Local bool
}

// Control is one control of a scan.
type Control struct {
	ID     string
	Plugin plugin.Control
}

// Finalizer evaluates the policy and the gate after the controls. Phase 5
// sets it. Nil gives no gate.
type Finalizer func(ctx context.Context, scan *state.Scan) (report.Gate, error)

// Options configure a scan.
type Options struct {
	Store *state.Store
	// Cache is the enrichment cache, or nil.
	Cache *state.Cache
	// NoCacheRead makes the scan fetch every package again. The scan still
	// writes the fresh results to the cache (--no-cache).
	NoCacheRead bool
	Source      plugin.Source
	// Extractors returns the extractors for an artifact kind.
	Extractors func(plugin.ArtifactKind) ([]plugin.Extractor, error)
	Enrichers  []Enricher
	Controls   []Control
	// Exclude holds glob patterns of paths to skip, relative to the root.
	Exclude []string

	Kind        report.ScanKind
	Mode        report.ScanMode
	BaseRef     string
	OptionsHash string
	VetVersion  string

	Resume         bool
	Fresh          bool
	ContinueWithin time.Duration
	// Strict makes any diagnostic fail the scan with exit code 3.
	Strict bool

	// BatchSize is the number of packages for each enricher call.
	BatchSize int

	Finalize Finalizer
	Observer Observer
	Now      func() time.Time
}

// Result is the outcome of a scan.
type Result struct {
	Scan  *state.Scan
	Entry *state.IndexEntry
	// Continued reports that the run continued a stopped scan.
	Continued bool
	// NotContinued is set when a stopped scan exists that the run did not
	// continue, with the reason.
	NotContinued *state.ContinueDecision
}

// ErrStrict means that --strict turned a diagnostic into a failure.
var ErrStrict = errors.New("engine: a diagnostic failed the scan in strict mode")

// Run runs a scan. The caller closes Result.Scan. When ctx stops, Run
// marks the scan interrupted, keeps its progress, and returns an error that
// wraps app.ErrInterrupted.
func Run(ctx context.Context, o Options) (*Result, error) {
	o.defaults()

	artifacts, err := collect(ctx, o.Source)
	if err != nil {
		return nil, err
	}
	defer closeArtifacts(artifacts)

	res, err := open(ctx, o, artifacts[0])
	if err != nil {
		return nil, err
	}
	run := &run{o: o, res: res, started: o.Now()}

	err = run.stages(ctx, artifacts)
	if finishErr := run.finish(ctx, err); finishErr != nil {
		err = errors.Join(err, finishErr)
	}
	if err != nil {
		if ctx.Err() != nil {
			return res, fmt.Errorf("%w: %w", app.ErrInterrupted, err)
		}
		return res, err
	}
	return res, nil
}

func (o *Options) defaults() {
	if o.Observer == nil {
		o.Observer = NopObserver{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.Kind == "" {
		o.Kind = report.ScanKindScan
	}
	if o.Mode == "" {
		o.Mode = report.ScanModeFull
		if o.BaseRef != "" {
			o.Mode = report.ScanModeDelta
		}
	}
}

func collect(ctx context.Context, src plugin.Source) ([]plugin.Artifact, error) {
	var out []plugin.Artifact
	for a, err := range src.Artifacts(ctx) {
		if err != nil {
			closeArtifacts(out)
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("engine: the source yielded no artifact")
	}
	return out, nil
}

func closeArtifacts(as []plugin.Artifact) {
	for _, a := range as {
		if a.Close == nil {
			continue
		}
		if err := a.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "vet: free %s: %v\n", a.Label, err)
		}
	}
}

// open continues a stopped scan of the target, or creates a new one.
func open(ctx context.Context, o Options, first plugin.Artifact) (*Result, error) {
	d, err := o.Store.DecideContinue(ctx, state.ContinueRequest{
		TargetKey: first.Key, OptionsHash: o.OptionsHash, VetVersion: o.VetVersion,
		Within: o.ContinueWithin, Resume: o.Resume, Fresh: o.Fresh, Now: o.Now(),
	})
	if err != nil {
		return nil, err
	}
	if o.Resume && d.Continue == nil {
		return nil, app.UsageError("--resume: no stopped scan of this target to continue",
			"Run vet scan without --resume to start a new scan.")
	}
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	res := &Result{}
	if d.Stopped != nil {
		res.NotContinued = d
	}
	if d.Continue != nil {
		scan, err := o.Store.ContinueScan(ctx, d.Continue, os.Getpid(), host)
		if err != nil {
			return nil, err
		}
		res.Scan, res.Entry, res.Continued = scan, d.Continue, true
		h := scan.Header()
		if h != nil {
			h.Scan.Continued = true
			if err := scan.SetHeader(ctx, h); err != nil {
				return nil, errors.Join(err, scan.Close())
			}
		}
		return res, nil
	}

	scan, entry, err := o.Store.CreateScan(ctx, state.NewScan{
		TargetKey: first.Key, TargetLabel: first.Label, Kind: o.Kind,
		OptionsHash: o.OptionsHash, VetVersion: o.VetVersion, Host: host, PID: os.Getpid(),
	})
	if err != nil {
		return nil, err
	}
	h := &report.Header{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.Tool{Name: "vet", Version: o.VetVersion},
		Scan: report.ScanInfo{
			ID: entry.ID, Kind: o.Kind, Mode: o.Mode, Target: first.Label, TargetKey: first.Key,
			StartedAt: entry.StartedAt, BaseRef: o.BaseRef,
		},
	}
	if err := scan.SetHeader(ctx, h); err != nil {
		return nil, errors.Join(err, scan.Close())
	}
	res.Scan, res.Entry = scan, entry
	return res, nil
}

type run struct {
	o         Options
	res       *Result
	started   time.Time
	diags     *diagnostics
	artifacts []plugin.Artifact
}

// rootOf returns the file system that a manifest was read from, for the
// controls that read the manifest file. A scan has one artifact today. An
// endpoint audit with many artifacts needs the artifact key of the
// manifest here.
func (r *run) rootOf(m *model.Manifest) fs.FS {
	if m.Kind == model.ManifestKindPURL || len(r.artifacts) == 0 {
		return nil
	}
	if r.artifacts[0].Kind == plugin.ArtifactEndpoint {
		return osFS{}
	}
	return r.artifacts[0].Root
}

// osFS opens the absolute slash paths of the files of an endpoint.
type osFS struct{}

func (osFS) Open(name string) (fs.File, error) { return os.Open(filepath.FromSlash(name)) }

func (r *run) stages(ctx context.Context, artifacts []plugin.Artifact) error {
	r.diags = newDiagnostics()
	r.artifacts = artifacts
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{StageExtract, func(ctx context.Context) error { return r.extract(ctx, artifacts) }},
		{StageEnrich, r.enrich},
		{StageEvaluate, r.evaluate},
	}
	for i, s := range steps {
		r.o.Observer.Stage(s.name, i+1, len(steps)+1)
		if err := r.res.Scan.SetStage(ctx, s.name, "running"); err != nil {
			return err
		}
		if err := s.fn(ctx); err != nil {
			return err
		}
		if err := r.res.Scan.SetStage(ctx, s.name, "done"); err != nil {
			return err
		}
	}
	r.o.Observer.Stage(StageReport, len(steps)+1, len(steps)+1)
	return nil
}

// finish writes the diagnostics, the gate and the trailer, and updates the
// index. A scan that failed or stopped gets no trailer.
func (r *run) finish(ctx context.Context, runErr error) error {
	// A stopped context must not lose the last writes of the run.
	wctx := context.WithoutCancel(ctx)
	scan, entry := r.res.Scan, r.res.Entry

	entry.RunTime += r.o.Now().Sub(r.started)
	entry.UpdatedAt = r.o.Now().UTC()

	var errs []error
	if r.diags != nil {
		errs = append(errs, r.diags.flush(wctx, scan))
	}
	switch {
	case runErr != nil && ctx.Err() != nil:
		entry.Status = state.StatusInterrupted
	case runErr != nil:
		entry.Status = state.StatusFailed
	default:
		gate := report.Gate{Outcome: report.GateNone}
		if r.o.Finalize != nil {
			g, err := r.o.Finalize(wctx, scan)
			if err != nil {
				errs = append(errs, err)
				entry.Status = state.StatusFailed
				break
			}
			gate = g
		}
		trailer, err := Trailer(wctx, scan, gate, r.o.Now())
		if err != nil {
			errs = append(errs, err)
			entry.Status = state.StatusFailed
			break
		}
		if err := scan.SetTrailer(wctx, trailer); err != nil {
			errs = append(errs, err)
			entry.Status = state.StatusFailed
			break
		}
		entry.Status = state.StatusCompleted
		entry.FinishedAt = r.o.Now().UTC()
		entry.Gate = string(gate.Outcome)
		entry.Packages, entry.Findings = trailer.Summary.Packages, trailer.Summary.Findings
		if r.o.Strict && r.diags.total > 0 {
			errs = append(errs, ErrStrict)
		}
	}
	if size, err := scan.Size(); err == nil {
		entry.SizeBytes = size
	}
	errs = append(errs, r.o.Store.Index().Update(wctx, entry))
	return errors.Join(errs...)
}

// Trailer summarizes the records of a scan.
func Trailer(ctx context.Context, scan plugin.Report, gate report.Gate, now time.Time) (*report.Trailer, error) {
	sum := report.NewSummary()
	var n uint64
	for rec, err := range scan.Records(ctx) {
		if err != nil {
			return nil, err
		}
		sum.Add(*rec)
		n++
	}
	return &report.Trailer{Summary: sum, Gate: gate, RecordCount: n, FinishedAt: now.UTC()}, nil
}

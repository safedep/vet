// Package symbols finds the vulnerable functions of a vulnerability: the
// fix sites of its record in the signed bundle of vuln-symbols. vet reads
// a list of sources, so a tenant source can join the public bundle later.
package symbols

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	vsym "github.com/safedep/vuln-symbols/symbols"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// The diagnostic codes of symbol data. A scan never fails because of
// symbol data, so each one is a warning.
const (
	CodeStale       = "symbol_data_stale"
	CodeUnreachable = "symbol_data_unreachable"
	CodeMissing     = "symbol_data_missing"
	CodeRejected    = "symbol_data_rejected"
)

// staleAfter is the age of a bundle signature that vet warns about. A host
// that stops publishing looks the same as a database with no new
// advisories.
const staleAfter = 7 * 24 * time.Hour

// Query asks for the records of one vulnerability of a package version.
type Query struct {
	Package model.PackageVersion
	// IDs are the id and the aliases of the vulnerability. The first is the
	// id that Insights gives.
	IDs []string
}

// Source finds the symbol records of vulnerabilities.
type Source interface {
	// Prepare makes the records ready. It can fetch, and it never fails:
	// a problem is a diagnostic.
	Prepare(ctx context.Context)
	// Lookup returns the records of each query, by the index of the query.
	Lookup(qs []Query) [][]model.SymbolRecord
	Diagnostics() []report.Diagnostic
	// Bundle describes the data of the scan, or nil with none.
	Bundle() *report.SymbolBundle
}

// Options configure the public bundle.
type Options struct {
	// CacheDir is the vet cache directory. The SDK keeps the verified
	// bundle in a subdirectory.
	CacheDir string
	// Update asks the host for a newer bundle, at most once a day.
	Update bool
	// LocalBundle reads a copy of the host files from a directory.
	LocalBundle string
	// Pin keeps the client on one bundle id.
	Pin string
	Now func() time.Time
}

// client is the part of the SDK client that vet calls.
type client interface {
	Update(ctx context.Context) (vsym.Status, error)
	Load(ctx context.Context) (*vsym.Bundle, error)
}

// Public is the signed public bundle of vuln-symbols.
type Public struct {
	client client
	update bool
	now    func() time.Time

	once   sync.Once
	bundle *vsym.Bundle
	diags  []report.Diagnostic
}

var _ Source = (*Public)(nil)

// NewPublic returns the public bundle source.
func NewPublic(o Options) (*Public, error) {
	opts := []vsym.Option{vsym.WithCacheDir(filepath.Join(o.CacheDir, "vuln-symbols"))}
	if o.LocalBundle != "" {
		opts = append(opts, vsym.WithLocalBundle(o.LocalBundle))
	}
	if o.Pin != "" {
		opts = append(opts, vsym.WithPin(o.Pin))
	}
	if !o.Update {
		opts = append(opts, vsym.WithOffline())
	}
	c, err := vsym.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("symbol data: %w", err)
	}
	return newPublic(c, o), nil
}

func newPublic(c client, o Options) *Public {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Public{client: c, update: o.Update, now: now}
}

// Prepare updates and loads the bundle once for the scan.
func (p *Public) Prepare(ctx context.Context) {
	p.once.Do(func() { p.prepare(ctx) })
}

func (p *Public) prepare(ctx context.Context) {
	if p.update {
		if _, err := p.client.Update(ctx); err != nil && ctx.Err() == nil {
			p.warn(updateCode(err), fmt.Sprintf("vet kept its symbol data, because the update failed: %v", err))
		}
	}
	b, err := p.client.Load(ctx)
	switch {
	case errors.Is(err, vsym.ErrNoBundle):
		p.warn(CodeMissing, "vet has no symbol data yet, so it cannot tell which functions a vulnerability is in. A scan with network access fetches it.")
		return
	case err != nil:
		p.warn(CodeRejected, fmt.Sprintf("vet cannot read its symbol data: %v", err))
		return
	}
	p.bundle = b
	if signed := b.Info().SignedAt; stale(signed, p.now()) {
		p.warn(CodeStale, fmt.Sprintf("the symbol data is from %s, more than 7 days ago", signed.UTC().Format(time.DateOnly)))
	}
	log.Debugf("symbol data: bundle %s with %d records", b.Info().ID, b.Info().Records)
}

// stale reports a signature older than staleAfter. A bundle with no
// verified time, as a local bundle in a test, is not stale.
func stale(signed, now time.Time) bool {
	return !signed.IsZero() && now.Sub(signed) > staleAfter
}

// updateCode tells a host that does not answer from a bundle that fails a
// check. The SDK gives no error types, so a transport error and an HTTP
// status are unreachable, and any other error is a rejected bundle.
func updateCode(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) || strings.Contains(err.Error(), ": status ") {
		return CodeUnreachable
	}
	return CodeRejected
}

func (p *Public) warn(code, msg string) {
	p.diags = append(p.diags, report.Diagnostic{Level: report.DiagnosticWarning, Code: code, Message: msg})
}

// Lookup matches each query by the alias set, the package name and the
// affected version range.
func (p *Public) Lookup(qs []Query) [][]model.SymbolRecord {
	out := make([][]model.SymbolRecord, len(qs))
	if p.bundle == nil {
		return out
	}
	for i, q := range qs {
		if len(q.IDs) == 0 {
			continue
		}
		for _, a := range p.bundle.Lookup(vsym.Query{Package: q.Package.Identity(), IDs: q.IDs}) {
			vs := a.Affected.DatabaseSpecific.VulnSymbols
			out[i] = append(out[i], model.SymbolRecord{
				Advisory: q.IDs[0],
				Record:   a.Record.ID,
				Coverage: vs.Coverage,
				Verified: vs.Review.State == vsym.ReviewVerified,
				FixSites: a.Affected.Names(),
			})
		}
	}
	return out
}

// Diagnostics returns the problems of the symbol data.
func (p *Public) Diagnostics() []report.Diagnostic { return p.diags }

// Bundle describes the loaded bundle.
func (p *Public) Bundle() *report.SymbolBundle {
	if p.bundle == nil {
		return nil
	}
	info := p.bundle.Info()
	return &report.SymbolBundle{ID: info.ID, SignedAt: info.SignedAt, Records: info.Records}
}

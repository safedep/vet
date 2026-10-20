package symbols

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	vsym "github.com/safedep/vuln-symbols/symbols"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

// fakeClient stands for the SDK client. The SDK tests its own signature,
// hash and rollback checks, so the fake decides the outcome.
type fakeClient struct {
	updateErr error
	bundle    *vsym.Bundle
	loadErr   error
	updates   int
}

func (f *fakeClient) Update(context.Context) (vsym.Status, error) {
	f.updates++
	return vsym.Status{Checked: true}, f.updateErr
}

func (f *fakeClient) Load(context.Context) (*vsym.Bundle, error) { return f.bundle, f.loadErr }

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// bundleOf builds a bundle of synthetic records, as the host serves it.
func bundleOf(t *testing.T, records ...vsym.Record) *vsym.Bundle {
	t.Helper()
	var lines bytes.Buffer
	for _, r := range records {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		lines.Write(append(b, '\n'))
	}
	var file bytes.Buffer
	zw := gzip.NewWriter(&file)
	_, err := zw.Write(lines.Bytes())
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	sha := hexSum(file.Bytes())
	b, err := vsym.ReadBundle(vsym.Manifest{
		Format: vsym.Format, AsOf: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Records: len(records),
		Bundle: vsym.BundleRef{Path: "bundles/" + sha + ".jsonl.gz", Size: int64(file.Len()), SHA256: sha, ContentSHA256: hexSum(lines.Bytes())},
	}, file.Bytes())
	require.NoError(t, err)
	return b
}

func goRecord(id, alias, module, fixed string, verified bool, fixSites ...string) vsym.Record {
	var sites []vsym.Symbol
	for _, s := range fixSites {
		sites = append(sites, vsym.Symbol{Name: s})
	}
	state := vsym.ReviewUnreviewed
	if verified {
		state = vsym.ReviewVerified
	}
	return vsym.Record{
		SchemaVersion: vsym.SchemaVersion, ID: id, Modified: "2026-09-01T00:00:00Z", Aliases: []string{alias},
		Affected: []vsym.Affected{{
			Package: vsym.Package{Ecosystem: "Go", Name: module},
			Ranges:  []vsym.Range{{Type: "SEMVER", Events: []vsym.Event{{Introduced: "0"}, {Fixed: fixed}}}},
			DatabaseSpecific: vsym.AffectedDatabase{VulnSymbols: vsym.VulnSymbols{
				Format: 1, Language: vsym.LanguageGo, Methods: []string{vsym.MethodUpstream},
				Coverage: vsym.CoverageExact, FixSites: sites, Review: vsym.Review{State: state},
			}},
		}},
		DatabaseSpecific: vsym.RecordDatabase{License: "CC-BY-4.0"},
	}
}

func TestLookup(t *testing.T) {
	b := bundleOf(t,
		goRecord("GO-2026-0001", "CVE-2026-0001", "example.com/net", "v0.5.0", true, "example.com/net/html.Render"),
		goRecord("GO-2026-0002", "CVE-2026-0002", "example.com/net", "v0.3.0", false, "example.com/net/http2.Read"),
	)
	p := newPublic(&fakeClient{bundle: b}, Options{})
	p.Prepare(context.Background())

	net := model.MustPackageVersion(model.EcosystemGo, "example.com/net", "v0.4.0")
	got := p.Lookup([]Query{
		{Package: net, IDs: []string{"GHSA-aaaa", "CVE-2026-0001"}},
		{Package: net, IDs: []string{"GHSA-bbbb", "CVE-2026-0002"}},
		{Package: net, IDs: []string{"GHSA-cccc"}},
		{Package: net},
	})
	require.Len(t, got, 4)
	assert.Equal(t, []model.SymbolRecord{{
		Advisory: "GHSA-aaaa", Record: "GO-2026-0001", Coverage: vsym.CoverageExact, Verified: true,
		Review: vsym.ReviewVerified, Source: SourceName, License: "CC-BY-4.0",
		FixSites: []string{"example.com/net/html.Render"},
	}}, got[0], "an alias of the Insights id matches the record")
	assert.Empty(t, got[1], "v0.4.0 is past the fix of the second record")
	assert.Empty(t, got[2], "an advisory with no record has no symbols")
	assert.Empty(t, got[3], "a query with no id asks for nothing")

	info := p.Bundle()
	require.NotNil(t, info)
	assert.Equal(t, 2, info.Records)
	assert.Empty(t, p.Diagnostics())
}

func TestPrepare(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	unreachable := &url.Error{Op: "Get", URL: "https://vuln-data.safedep.io/v1/manifest.json", Err: errors.New("no route to host")}
	cases := []struct {
		name    string
		client  *fakeClient
		update  bool
		codes   []string
		updates int
		bundle  bool
	}{
		{name: "an update and a fresh bundle", client: &fakeClient{bundle: &vsym.Bundle{}}, update: true, updates: 1, bundle: true},
		{name: "update off asks no host", client: &fakeClient{bundle: &vsym.Bundle{}}, bundle: true},
		{
			name: "an unreachable host keeps the cached bundle", client: &fakeClient{updateErr: fmt.Errorf("fetch manifest.json: %w", unreachable), bundle: &vsym.Bundle{}},
			update: true, updates: 1, codes: []string{CodeUnreachable}, bundle: true,
		},
		{
			name: "an HTTP error is unreachable", client: &fakeClient{updateErr: errors.New("fetch manifest.json: status 503 Service Unavailable"), bundle: &vsym.Bundle{}},
			update: true, updates: 1, codes: []string{CodeUnreachable}, bundle: true,
		},
		{
			name: "a bad signature keeps the cached bundle and names the reason", client: &fakeClient{updateErr: errors.New("verify the signature: certificate identity mismatch"), bundle: &vsym.Bundle{}},
			update: true, updates: 1, codes: []string{CodeRejected}, bundle: true,
		},
		{name: "no bundle yet", client: &fakeClient{loadErr: vsym.ErrNoBundle}, codes: []string{CodeMissing}},
		{
			name: "an offline first scan", client: &fakeClient{updateErr: fmt.Errorf("fetch manifest.json: %w", unreachable), loadErr: vsym.ErrNoBundle},
			update: true, updates: 1, codes: []string{CodeUnreachable, CodeMissing},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPublic(c.client, Options{Update: c.update, Now: func() time.Time { return now }})
			p.Prepare(context.Background())
			p.Prepare(context.Background())
			assert.Equal(t, c.updates, c.client.updates, "a scan asks the host at most once")
			var codes []string
			for _, d := range p.Diagnostics() {
				codes = append(codes, d.Code)
			}
			assert.Equal(t, c.codes, codes)
			assert.Equal(t, c.bundle, p.bundle != nil)
		})
	}
}

func TestStale(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	assert.False(t, Stale(time.Time{}, now), "a bundle with no verified time is not stale")
	assert.False(t, Stale(now.Add(-6*24*time.Hour), now))
	assert.True(t, Stale(now.Add(-8*24*time.Hour), now))
}

func TestNoBundleMatchesNothing(t *testing.T) {
	p := newPublic(&fakeClient{loadErr: vsym.ErrNoBundle}, Options{})
	p.Prepare(context.Background())
	got := p.Lookup([]Query{{Package: model.MustPackageVersion(model.EcosystemGo, "example.com/net", "v0.4.0"), IDs: []string{"GHSA-aaaa"}}})
	assert.Equal(t, [][]model.SymbolRecord{nil}, got)
	assert.Nil(t, p.Bundle())
}

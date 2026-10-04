package state

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/report"
)

func TestOptionsHash(t *testing.T) {
	type opts struct {
		Target     string
		IncludeDev bool
	}
	a, err := OptionsHash(opts{Target: "/r"})
	require.NoError(t, err)
	b, err := OptionsHash(opts{Target: "/r"})
	require.NoError(t, err)
	c, err := OptionsHash(opts{Target: "/r", IncludeDev: true})
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Len(t, a, 64)
}

func TestScanLock(t *testing.T) {
	s := openStore(t)
	scan, e := newScan(t, s, "/repo")

	live, err := isLive(e.File)
	require.NoError(t, err)
	assert.True(t, live)

	_, err = s.ContinueScan(context.Background(), e, 1, "h")
	assert.ErrorIs(t, err, ErrLocked)

	require.NoError(t, scan.Close())
	live, err = isLive(e.File)
	require.NoError(t, err)
	assert.False(t, live)
}

func TestDecideContinue(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	base := ContinueRequest{TargetKey: "/repo", OptionsHash: "h1", VetVersion: "test", Now: now}

	cases := []struct {
		name      string
		stopAgo   time.Duration
		keepLive  bool
		noScan    bool
		req       func(ContinueRequest) ContinueRequest
		continues bool
		reason    Reason
	}{
		{name: "same inputs continue", stopAgo: time.Hour, continues: true},
		{name: "no stopped scan", noScan: true},
		{name: "fresh", stopAgo: time.Hour, req: func(r ContinueRequest) ContinueRequest { r.Fresh = true; return r }, reason: ReasonFresh},
		{name: "options changed", stopAgo: time.Hour, req: func(r ContinueRequest) ContinueRequest { r.OptionsHash = "h2"; return r }, reason: ReasonOptionsChanged},
		{name: "version changed", stopAgo: time.Hour, req: func(r ContinueRequest) ContinueRequest { r.VetVersion = "2"; return r }, reason: ReasonVersionChanged},
		{name: "too old", stopAgo: 25 * time.Hour, reason: ReasonTooOld},
		{name: "resume ignores age", stopAgo: 72 * time.Hour, req: func(r ContinueRequest) ContinueRequest { r.Resume = true; return r }, continues: true},
		{name: "custom window", stopAgo: 2 * time.Hour, req: func(r ContinueRequest) ContinueRequest { r.Within = time.Hour; return r }, reason: ReasonTooOld},
		{name: "live scan does not continue", keepLive: true, reason: ReasonLive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := openStore(t)
			var entry *IndexEntry
			if !tc.noScan {
				var scan *Scan
				scan, entry = newScan(t, s, "/repo")
				entry.UpdatedAt = now.Add(-tc.stopAgo)
				require.NoError(t, s.Index().Update(ctx, entry))
				if !tc.keepLive {
					require.NoError(t, scan.Close())
				}
			}
			req := base
			if tc.req != nil {
				req = tc.req(req)
			}
			d, err := s.DecideContinue(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, tc.reason, d.Reason)
			if tc.continues {
				require.NotNil(t, d.Continue)
				assert.Equal(t, entry.ID, d.Continue.ID)
				assert.Nil(t, d.Stopped)
				return
			}
			assert.Nil(t, d.Continue)
			if tc.noScan {
				assert.Nil(t, d.Stopped)
				return
			}
			require.NotNil(t, d.Stopped)
			assert.Equal(t, entry.ID, d.Stopped.ID)

			got, err := s.Index().Get(ctx, entry.ID)
			require.NoError(t, err)
			want := StatusInterrupted
			if tc.keepLive {
				want = StatusRunning
			}
			assert.Equal(t, want, got.Status)
		})
	}
}

func TestContinueScan(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	scan, e := newScan(t, s, "/repo")
	require.NoError(t, scan.SetHeader(ctx, &report.Header{SchemaVersion: report.SchemaVersion}))
	require.NoError(t, scan.AddManifest(ctx, "", lockfile()))
	require.NoError(t, scan.Close())

	d, err := s.DecideContinue(ctx, ContinueRequest{TargetKey: "/repo", OptionsHash: "h1", VetVersion: "test"})
	require.NoError(t, err)
	require.NotNil(t, d.Continue)

	cont, err := s.ContinueScan(ctx, d.Continue, 42, "host")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cont.Close()) })
	assert.Equal(t, report.SchemaVersion, cont.Header().SchemaVersion)

	got, err := s.Index().Get(ctx, e.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, got.Status)
	assert.True(t, got.Continued)
	assert.Equal(t, 42, got.PID)

	live, err := isLive(e.File)
	require.NoError(t, err)
	assert.True(t, live)
}

// TestStoppedScanWithNoFile checks that vet starts a new scan in place of a
// stopped scan with no scan file, and does not make an empty scan file.
func TestStoppedScanWithNoFile(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	scan, e := newScan(t, s, "/repo")
	require.NoError(t, scan.Close())
	require.NoError(t, os.Remove(e.File))

	d, err := s.DecideContinue(ctx, ContinueRequest{TargetKey: "/repo", OptionsHash: "h1", VetVersion: "test"})
	require.NoError(t, err)
	assert.Nil(t, d.Continue)
	assert.Equal(t, ReasonFileMissing, d.Reason)
	assert.NoFileExists(t, e.File)
}

// TestScanOfAnotherFormat checks that vet refuses a scan file of another
// format, and starts a new scan in place of a stopped one of that format.
func TestScanOfAnotherFormat(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	scan, e := newScan(t, s, "/repo")
	require.NoError(t, scan.setMeta(ctx, metaFormat, scanFormat-1))
	require.NoError(t, scan.Close())

	_, err := s.OpenScan(ctx, e)
	var ue usefulerror.UsefulError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, CodeScanFormat, ue.Code())

	d, err := s.DecideContinue(ctx, ContinueRequest{TargetKey: "/repo", OptionsHash: "h1", VetVersion: "test"})
	require.NoError(t, err)
	assert.Nil(t, d.Continue)
	assert.Equal(t, ReasonVersionChanged, d.Reason)
}

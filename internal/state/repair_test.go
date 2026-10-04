package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/report"
)

func TestInspectAndRepair(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)

	// A running scan whose process stopped: its lock is gone.
	stale, staleEntry, err := s.CreateScan(ctx, NewScan{TargetKey: "/a", TargetLabel: ".", Kind: "scan", OptionsHash: "h", VetVersion: "test"})
	require.NoError(t, err)
	require.NoError(t, stale.Close())

	// An entry whose file is gone.
	gone, goneEntry, err := s.CreateScan(ctx, NewScan{TargetKey: "/b", TargetLabel: ".", Kind: "scan", OptionsHash: "h", VetVersion: "test"})
	require.NoError(t, err)
	require.NoError(t, gone.Close())
	require.NoError(t, os.Remove(goneEntry.File))

	// A scan file with no entry.
	orphan, orphanEntry, err := s.CreateScan(ctx, NewScan{TargetKey: "/c", TargetLabel: "c", Kind: "scan", OptionsHash: "h", VetVersion: "test"})
	require.NoError(t, err)
	require.NoError(t, orphan.SetHeader(ctx, &report.Header{
		SchemaVersion: report.SchemaVersion, Tool: report.Tool{Name: "vet", Version: "test"},
		Scan: report.ScanInfo{ID: orphanEntry.ID, Kind: report.ScanKindScan, Target: "c", TargetKey: "/c", StartedAt: orphanEntry.StartedAt},
	}))
	require.NoError(t, orphan.Close())
	require.NoError(t, s.Index().Delete(ctx, orphanEntry.ID))

	// A live scan is not an issue.
	_, _ = newScan(t, s, "/d")

	is, err := s.Inspect(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{staleEntry.ID}, ids(is.StaleRunning))
	assert.Equal(t, []string{goneEntry.ID}, ids(is.MissingFiles))
	require.Len(t, is.Orphans, 1)
	assert.Equal(t, filepath.Clean(orphanEntry.File), filepath.Clean(is.Orphans[0]))

	require.NoError(t, s.Repair(ctx, is))
	again, err := s.Inspect(ctx)
	require.NoError(t, err)
	assert.True(t, again.Empty(), "the repair fixes every issue")

	e, err := s.Index().Get(ctx, staleEntry.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusInterrupted, e.Status)
	o, err := s.Index().Get(ctx, orphanEntry.ID)
	require.NoError(t, err)
	assert.Equal(t, "/c", o.TargetKey)
	assert.Equal(t, StatusInterrupted, o.Status, "a scan file with no trailer is interrupted")
}

// TestRepairDeletesAnOrphanOfAnotherFormat checks that a repair does not
// index a scan file that this vet cannot open.
func TestRepairDeletesAnOrphanOfAnotherFormat(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	old, e, err := s.CreateScan(ctx, NewScan{TargetKey: "/old", TargetLabel: ".", Kind: "scan", OptionsHash: "h", VetVersion: "test"})
	require.NoError(t, err)
	require.NoError(t, old.SetHeader(ctx, &report.Header{SchemaVersion: report.SchemaVersion, Scan: report.ScanInfo{ID: e.ID, TargetKey: "/old"}}))
	require.NoError(t, old.setMeta(ctx, metaFormat, scanFormat-1))
	require.NoError(t, old.Close())
	require.NoError(t, s.Index().Delete(ctx, e.ID))

	is, err := s.Inspect(ctx)
	require.NoError(t, err)
	require.Len(t, is.Orphans, 1)
	require.NoError(t, s.Repair(ctx, is))

	assert.NoFileExists(t, e.File)
	_, err = s.Index().Get(ctx, e.ID)
	assert.Error(t, err, "the repair adds no entry for the old scan")
	again, err := s.Inspect(ctx)
	require.NoError(t, err)
	assert.True(t, again.Empty())
}

package state

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func entry(id, target string, st Status, age time.Duration, size int64) *IndexEntry {
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).Add(-age)
	return &IndexEntry{ID: id, TargetKey: target, Status: st, StartedAt: at, UpdatedAt: at, SizeBytes: size}
}

func ids(es []*IndexEntry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.ID)
	}
	return out
}

func TestRetentionSelect(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name    string
		r       Retention
		entries []*IndexEntry
		want    []string
	}{
		{
			name: "per target keeps the newest",
			r:    Retention{PerTarget: 2},
			entries: []*IndexEntry{
				entry("a3", "a", StatusCompleted, 1*day, 1), entry("b1", "b", StatusCompleted, 2*day, 1),
				entry("a2", "a", StatusCompleted, 3*day, 1), entry("a1", "a", StatusCompleted, 4*day, 1),
			},
			want: []string{"a1"},
		},
		{
			name: "old interrupted and failed scans go",
			r:    Retention{Interrupted: 7 * day},
			entries: []*IndexEntry{
				entry("i2", "a", StatusInterrupted, 1*day, 1), entry("f1", "a", StatusFailed, 8*day, 1),
				entry("i1", "a", StatusInterrupted, 9*day, 1), entry("r1", "a", StatusRunning, 30*day, 1),
			},
			want: []string{"i1", "f1"},
		},
		{
			name: "size limit drops the oldest and keeps the last completed scan",
			r:    Retention{MaxSize: 250},
			entries: []*IndexEntry{
				entry("a2", "a", StatusCompleted, 1*day, 100), entry("b1", "b", StatusCompleted, 2*day, 100),
				entry("a1", "a", StatusCompleted, 3*day, 100), entry("i1", "b", StatusInterrupted, 4*day, 100),
			},
			want: []string{"i1", "a1"},
		},
		{
			name:    "no rule keeps everything",
			entries: []*IndexEntry{entry("a1", "a", StatusCompleted, 400*day, 1e9)},
			want:    []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ids(tc.r.Select(tc.entries, now)))
		})
	}
}

func TestDeleteScanAndRetention(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)

	running, live := newScan(t, s, "/a")
	err := s.DeleteScan(ctx, live)
	require.ErrorIs(t, err, ErrScanRunning, "a live scan stays")

	var done []*IndexEntry
	for range 3 {
		scan, e, err := s.CreateScan(ctx, NewScan{TargetKey: "/b", TargetLabel: ".", Kind: "scan", OptionsHash: "h", VetVersion: "test"})
		require.NoError(t, err)
		require.NoError(t, scan.Close())
		e.Status = StatusCompleted
		require.NoError(t, s.Index().Update(ctx, e))
		done = append(done, e)
		time.Sleep(10 * time.Millisecond)
	}

	u, err := s.Usage(ctx)
	require.NoError(t, err)
	assert.Equal(t, 4, u.Scans)
	assert.Equal(t, 2, u.Targets)
	assert.Positive(t, u.Bytes)

	deleted, err := s.ApplyRetention(ctx, Retention{PerTarget: 1}, time.Now())
	require.NoError(t, err)
	assert.Len(t, deleted, 2)
	for _, e := range deleted {
		_, err := os.Stat(e.File)
		assert.ErrorIs(t, err, os.ErrNotExist, "the scan file goes")
		_, err = s.Index().Get(ctx, e.ID)
		assert.ErrorIs(t, err, ErrNotFound, "the index entry goes")
	}
	_, err = s.Index().Get(ctx, done[2].ID)
	require.NoError(t, err, "the newest completed scan stays")
	assert.NotNil(t, running)
}

func TestCacheStats(t *testing.T) {
	ctx := context.Background()
	c, err := OpenCache(ctx, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, c.Close()) })
	st, err := c.Stats(ctx)
	require.NoError(t, err)
	assert.Zero(t, st.Entries)
	assert.True(t, st.Oldest.IsZero())
}

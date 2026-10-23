package humanize

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestElapsed(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0.0s"},
		{925 * time.Millisecond, "0.9s"},
		{2*time.Second + 140*time.Millisecond, "2.1s"},
		{9*time.Second + 960*time.Millisecond, "10s"},
		{42*time.Second + 600*time.Millisecond, "43s"},
		{59*time.Second + 600*time.Millisecond, "1m0s"},
		{2*time.Minute + 51545*time.Millisecond, "2m52s"},
		{65 * time.Minute, "1h5m"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, Elapsed(tc.d))
		})
	}
}

func TestCount(t *testing.T) {
	assert.Equal(t, "0 scans", Count(0, "scan"))
	assert.Equal(t, "1 scan", Count(1, "scan"))
	assert.Equal(t, "2 actions", Count(2, "action"))
}

func TestBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{n: 0, want: "0 B"},
		{n: 999, want: "999 B"},
		{n: 1000, want: "1.0 kB"},
		{n: 466944, want: "466.9 kB"},
		{n: 12062720, want: "12.1 MB"},
		{n: 2 * 1000 * 1000 * 1000, want: "2.0 GB"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, Bytes(tc.n))
		})
	}
}

func TestMinute(t *testing.T) {
	cest := time.FixedZone("CEST", 2*3600)
	cases := []struct {
		name         string
		t            time.Time
		down, upward string
	}{
		{"seconds", time.Date(2026, 10, 23, 11, 15, 31, 0, time.UTC), "2026-10-23 11:15 UTC", "2026-10-23 11:16 UTC"},
		{"a whole minute", time.Date(2026, 10, 23, 11, 15, 0, 0, time.UTC), "2026-10-23 11:15 UTC", "2026-10-23 11:15 UTC"},
		{"another zone", time.Date(2026, 10, 23, 11, 15, 1, 0, cest), "2026-10-23 09:15 UTC", "2026-10-23 09:16 UTC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.down, Minute(tc.t))
			assert.Equal(t, tc.upward, MinuteAfter(tc.t))
		})
	}
}

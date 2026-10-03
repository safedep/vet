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

package doctor

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/tui/checklist"
)

func TestSizeMessage(t *testing.T) {
	cases := []struct {
		name  string
		scans int
		used  int64
		limit string
		want  string
	}{
		{name: "limit", scans: 3, used: 12062720, limit: "2GB", want: "3 scans use 12.1 MB of the limit of 2GB"},
		{name: "no limit", scans: 0, used: 0, want: "0 scans use 0 B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sizeMessage(tc.scans, tc.used, tc.limit))
		})
	}
}

func TestStatusItem(t *testing.T) {
	for s, want := range map[Status]checklist.Status{Pass: checklist.Pass, Warn: checklist.Warn, Fail: checklist.Fail} {
		assert.Equal(t, want, s.item(), s)
	}
}

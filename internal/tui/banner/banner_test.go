package banner

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestPrintToShowsTheBannerOnlyToAHuman(t *testing.T) {
	prev := output.CurrentMode()
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetVerbosity(output.Normal)
	})
	cases := []struct {
		name      string
		mode      output.Mode
		verbosity output.Verbosity
		shown     bool
	}{
		{"rich", output.Rich, output.Normal, true},
		{"rich -v", output.Rich, output.Verbose, true},
		{"rich -q", output.Rich, output.Silent, false},
		{"plain", output.Plain, output.Normal, false},
		{"agent", output.Agent, output.Normal, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetMode(tc.mode)
			output.SetVerbosity(tc.verbosity)
			var b bytes.Buffer
			PrintTo(&b, "v2.0.1+dirty")
			if !tc.shown {
				assert.Empty(t, b.String())
				return
			}
			assert.Contains(t, b.String(), Tagline)
			assert.Contains(t, b.String(), "vet v2.0.1")
			assert.NotContains(t, b.String(), "+dirty")
		})
	}
}

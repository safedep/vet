package logging

import (
	"bytes"
	"io"
	stdlog "log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestStandardLogPrintsOnlyWithVerbose(t *testing.T) {
	CaptureStandardLog()
	t.Cleanup(func() {
		stdlog.SetOutput(os.Stderr)
		stdlog.SetFlags(stdlog.LstdFlags)
		output.SetWriters(os.Stdout, os.Stderr)
		output.SetVerbosity(output.Normal)
	})
	cases := []struct {
		name      string
		verbosity output.Verbosity
		want      string
	}{
		{"normal", output.Normal, ""},
		{"quiet", output.Silent, ""},
		{"verbose", output.Verbose, "could not extract pom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			output.SetWriters(io.Discard, &stderr)
			output.SetVerbosity(tc.verbosity)
			stdlog.Printf("could not extract pom from %s", "pom.xml")
			if tc.want == "" {
				assert.Empty(t, stderr.String())
				return
			}
			assert.Contains(t, stderr.String(), tc.want)
			assert.NotRegexp(t, `^\d{4}/\d{2}/\d{2}`, stderr.String(), "the line has no timestamp")
		})
	}
}

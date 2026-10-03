package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestGetPrintsTheBareValue(t *testing.T) {
	t.Cleanup(func() {
		output.SetWriters(os.Stdout, os.Stderr)
		output.SetMode(output.Rich)
	})
	output.SetMode(output.Plain)
	dir := t.TempDir()
	env := map[string]string{
		"VET_SCAN_CONCURRENCY": "3",
		"XDG_CONFIG_HOME":      dir, "XDG_STATE_HOME": dir, "XDG_CACHE_HOME": dir, "XDG_DATA_HOME": dir,
	}
	cases := []struct {
		format string
		check  func(t *testing.T, out string)
	}{
		{format: "table", check: func(t *testing.T, out string) { assert.Equal(t, "3\n", out) }},
		{format: "plain", check: func(t *testing.T, out string) { assert.Equal(t, "3\n", out) }},
		{format: "json", check: func(t *testing.T, out string) {
			var e Entry
			require.NoError(t, json.Unmarshal([]byte(out), &e))
			assert.Equal(t, "scan.concurrency", e.Key)
			assert.EqualValues(t, 3, e.Value)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			output.SetWriters(&stdout, &stderr)
			a := app.New(app.Options{LookupEnv: func(k string) (string, bool) {
				v, ok := env[k]
				return v, ok
			}})
			a.Globals.Output = tc.format
			c := newGet(a)
			c.SetArgs([]string{"scan.concurrency"})
			require.NoError(t, c.Execute())
			tc.check(t, stdout.String())
		})
	}
}

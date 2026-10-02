package version

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

func TestVersion(t *testing.T) {
	t.Cleanup(func() {
		output.SetWriters(os.Stdout, os.Stderr)
		output.SetMode(output.Rich)
	})
	output.SetMode(output.Plain)
	cases := []struct {
		name   string
		format string
		check  func(t *testing.T, out string)
	}{
		{name: "json", format: "json", check: func(t *testing.T, out string) {
			var i Info
			require.NoError(t, json.Unmarshal([]byte(out), &i))
			assert.Equal(t, Current(), i)
		}},
		{name: "plain", format: "plain", check: func(t *testing.T, out string) {
			assert.Contains(t, out, "VERSION\tCOMMIT\tGO\tPLATFORM\n")
			assert.Contains(t, out, Current().Platform)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			output.SetWriters(&stdout, &stderr)
			a := app.New(app.Options{})
			a.Globals.Output = tc.format
			c := New(a)
			c.SetArgs(nil)
			require.NoError(t, c.Execute())
			tc.check(t, stdout.String())
			assert.Empty(t, stderr.String())
		})
	}
}

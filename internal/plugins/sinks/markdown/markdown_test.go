package markdown

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestOneRowAndOneCardForEachCause(t *testing.T) {
	sink, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	var b bytes.Buffer
	require.NoError(t, sink.Write(context.Background(), plugintest.UpgradeReport(), &b))
	out := b.String()
	assert.Equal(t, 1, strings.Count(out, "`npm/pnpm@12.15.0` and 14 more |"), "one row for the release")
	assert.Equal(t, 1, strings.Count(out, "`npm/pnpm@12.15.0` and 14 more: **Published 1 day ago** · `cooldown`"), "one card for the release")
	assert.Contains(t, out, "<details><summary>14 more with this cause</summary>")
	assert.Contains(t, out, `**Fix:** Keep "packageManager" at pnpm@12.8.2 in package.json, or wait until 2026-10-23. The wait ends at 2026-10-23 11:17 UTC.`)
	assert.NotContains(t, out, "npm/@pnpm/exe.linux-x64@12.15.0` |", "a platform package has no row of its own")
}

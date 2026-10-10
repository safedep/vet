package hiddencode_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/controls/hiddencode"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func evaluate(t *testing.T, path, data string) []finding.Finding {
	t.Helper()
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: path, Kind: model.ManifestKindFile, Root: fstest.MapFS{path: {Data: []byte(data)}}}
	return plugintest.TestControl(t, c, m, nil)
}

func TestPaddedCode(t *testing.T) {
	fs := evaluate(t, "postcss.config.mjs", "const config = {};\nexport default config;"+strings.Repeat(" ", 280)+"eval(x)\n")
	require.Len(t, fs, 1)
	f := fs[0]
	assert.Equal(t, "padded-code", f.ControlID)
	assert.Equal(t, finding.FamilyHiddenCode, f.Family)
	assert.Equal(t, finding.SeverityCritical, f.Severity)
	assert.Equal(t, 2, f.Locus.StartLine)
	assert.Equal(t, "export default config;", f.Locus.Snippet)
	assert.NotContains(t, f.Locus.Snippet, "eval")
}

func TestOtherKindsAreSkipped(t *testing.T) {
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: "postcss.config.mjs", Kind: model.ManifestKindAgentConfig, Root: fstest.MapFS{}}
	assert.Empty(t, plugintest.TestControl(t, c, m, nil))
}

func TestDisguisedScript(t *testing.T) {
	fs := evaluate(t, "public/fonts/fa-solid-400.woff2", strings.Repeat("\t", 273)+"console.log(1)")
	require.Len(t, fs, 1)
	assert.Equal(t, "disguised-script", fs[0].ControlID)
	assert.Equal(t, finding.SeverityCritical, fs[0].Severity)
	assert.Equal(t, "The file has a .woff2 name but holds text, not a woff2 file, after 273 leading spaces and tabs", fs[0].Title)
}

func TestHistoryRewriteScript(t *testing.T) {
	fs := evaluate(t, ".gitignore", "node_modules\ntemp_auto_push.bat\n")
	require.Len(t, fs, 1)
	assert.Equal(t, "history-rewrite-script", fs[0].ControlID)
	assert.Equal(t, 2, fs[0].Locus.StartLine)
}

func TestCampaignInTheTitle(t *testing.T) {
	fs := evaluate(t, "postcss.config.mjs", "export default config;"+strings.Repeat(" ", 280)+"global['_V']='8-st14';eval(x)")
	require.Len(t, fs, 1)
	assert.Equal(t, "Code continues on line 1 after 280 spaces, with 29 bytes off screen. It matches PolinRider", fs[0].Title)
}

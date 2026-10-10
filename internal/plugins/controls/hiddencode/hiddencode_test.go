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

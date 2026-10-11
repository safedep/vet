package hiddencode_test

import (
	"context"
	"fmt"
	"slices"
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

var js = "(function(){var _0xa1b2=function(){return 1};" + strings.Repeat("var _0xc3d4=_0xa1b2();", 10) + "})();"

func evaluate(t *testing.T, path, data string) []finding.Finding {
	t.Helper()
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: path, Kind: model.ManifestKindFile, Root: fstest.MapFS{path: {Data: []byte(data)}}}
	return plugintest.TestControl(t, c, m, nil)
}

func TestPaddedCode(t *testing.T) {
	fs := evaluate(t, "postcss.config.mjs", "const config = {};\nexport default config;"+strings.Repeat(" ", 280)+js+"\n")
	require.Len(t, fs, 1)
	f := fs[0]
	assert.Equal(t, "padded-code", f.ControlID)
	assert.Equal(t, finding.FamilyHiddenCode, f.Family)
	assert.Equal(t, finding.SeverityCritical, f.Severity)
	assert.Equal(t, 2, f.Locus.StartLine)
	assert.Equal(t, "export default config;", f.Locus.Snippet)
	assert.NotContains(t, f.Locus.Snippet, "_0x")
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
	assert.Equal(t, "The file has a .woff2 name but holds a script or an encoded payload, not a woff2 file, after 273 leading spaces and tabs", fs[0].Title)
}

func TestHistoryRewriteScript(t *testing.T) {
	fs := evaluate(t, ".gitignore", "node_modules\ntemp_auto_push.bat\n")
	require.Len(t, fs, 1)
	assert.Equal(t, "history-rewrite-script", fs[0].ControlID)
	assert.Equal(t, 2, fs[0].Locus.StartLine)
}

func TestCampaignInTheTitle(t *testing.T) {
	fs := evaluate(t, "postcss.config.mjs", "export default config;"+strings.Repeat(" ", 280)+"global['_V']='8-st14';"+js)
	i := slices.IndexFunc(fs, func(f finding.Finding) bool { return f.ControlID == "padded-code" })
	require.GreaterOrEqual(t, i, 0)
	assert.Equal(t, fmt.Sprintf("Code continues on line 1 after 280 spaces, with %d bytes off screen. It matches PolinRider", len("global['_V']='8-st14';"+js)), fs[i].Title)
}

func hide(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		b.WriteRune(0xE0100 + rune(c) - 16)
	}
	return b.String()
}

func TestSplitPayload(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"two parts over the limit", map[string]string{"src/a.js": "x" + hide("console.log("), "src/b.js": "x" + hide("1);done;")}, []string{"src/a.js", "src/b.js"}},
		{"two parts under the limit", map[string]string{"src/a.js": "x" + hide("conso"), "src/b.js": "x" + hide("le.lo")}, nil},
		{"one part", map[string]string{"src/a.js": "x" + hide("console.log(1)")}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			root := fstest.MapFS{}
			for p, data := range tc.files {
				root[p] = &fstest.MapFile{Data: []byte("const s = '" + data + "';\n")}
			}
			for p := range tc.files {
				_, err := c.Evaluate(context.Background(), &model.Manifest{ID: p, Path: p, Kind: model.ManifestKindFile, Root: root}, nil)
				require.NoError(t, err)
			}
			fs, err := c.(plugin.ApplicationControl).EvaluateApplication(context.Background(), nil)
			require.NoError(t, err)
			var got []string
			for _, f := range fs {
				assert.Equal(t, "split-unicode-payload", f.ControlID)
				assert.NotContains(t, f.Locus.Snippet, "\U000E0100")
				got = append(got, f.Subject.File.Path)
			}
			assert.Equal(t, tc.want, got)
			again, err := c.(plugin.ApplicationControl).EvaluateApplication(context.Background(), nil)
			require.NoError(t, err)
			assert.Empty(t, again, "the next scan starts with no parts")
		})
	}
}

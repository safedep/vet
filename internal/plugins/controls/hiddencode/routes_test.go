package hiddencode_test

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/controls/hiddencode"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestScriptHookAddedOnlyForAHookThatTheBaseDidNotHave(t *testing.T) {
	head := fstest.MapFS{
		"package.json": {Data: []byte(`{"version":"2.0.0","scripts":{"postinstall":"node bin/setup","pretest":"node setup.js"}}`)},
		"setup.js":     {Data: []byte("console.log('setup')\n")},
		"bin/setup":    {Data: []byte("console.log('setup')\n")},
	}
	base := func(pkg string) fstest.MapFS {
		return fstest.MapFS{"package.json": {Data: []byte(pkg)}, "setup.js": head["setup.js"], "bin/setup": head["bin/setup"]}
	}
	cases := []struct {
		name   string
		change model.Change
		base   fstest.MapFS
		want   []string
	}{
		{"a full scan has no base", model.ChangeNone, nil, nil},
		{"the change adds both hooks", model.ChangeModified, base(`{"version":"1.0.0"}`), []string{"script-hook-added package.json", "script-hook-added package.json"}},
		{"the change adds a hook next to a hook of the base", model.ChangeModified, base(`{"version":"1.0.0","scripts":{"postinstall":"node bin/setup"}}`), []string{"script-hook-added package.json"}},
		{"the change edits only the version", model.ChangeModified, base(`{"version":"1.0.0","scripts":{"postinstall":"node bin/setup","pretest":"node setup.js"}}`), nil},
		{"a new package.json", model.ChangeAdded, fstest.MapFS{}, []string{"script-hook-added package.json", "script-hook-added package.json"}},
		{"the change keeps the package.json", model.ChangeUnchanged, base(`{"version":"2.0.0","scripts":{"postinstall":"node bin/setup","pretest":"node setup.js"}}`), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "package.json", Kind: model.ManifestKindFile, Change: tc.change, Root: head}
			if tc.base != nil {
				m.Base = tc.base
			}
			var got []string
			for _, f := range plugintest.TestControl(t, c, m, nil) {
				got = append(got, f.ControlID+" "+f.Locus.Path)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestScriptHookAddedWhenAHookGetsAnotherCandidate(t *testing.T) {
	base := fstest.MapFS{"package.json": {Data: []byte(`{"version":"1.0.0","scripts":{"pretest":"node tools"}}`)}, "tools.cjs": {Data: []byte("1\n")}}
	head := fstest.MapFS{"package.json": {Data: []byte(`{"version":"1.0.1","scripts":{"pretest":"node tools"}}`)}, "tools.cjs": {Data: []byte("1\n")}, "tools/index.js": {Data: []byte("2\n")}}
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: "package.json", Kind: model.ManifestKindFile, Change: model.ChangeModified, Root: head, Base: base}
	fs := plugintest.TestControl(t, c, m, nil)
	require.Len(t, fs, 1, "the hook can now run tools/index.js too")
	assert.Equal(t, "script-hook-added", fs[0].ControlID)
}

func TestScriptHookAddedWhenAHookRunsAnotherFile(t *testing.T) {
	pkg := func(file string) []byte {
		return []byte(`{"scripts":{"pretest":"npm run setup","setup":"node ` + file + `"}}`)
	}
	files := func(p []byte) fstest.MapFS {
		return fstest.MapFS{"package.json": {Data: p}, "a.js": {Data: []byte("1\n")}, "b.js": {Data: []byte("2\n")}}
	}
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: "package.json", Kind: model.ManifestKindFile, Change: model.ChangeModified, Root: files(pkg("b.js")), Base: files(pkg("a.js"))}
	fs := plugintest.TestControl(t, c, m, nil)
	require.Len(t, fs, 1)
	assert.Equal(t, "script-hook-added", fs[0].ControlID)
}

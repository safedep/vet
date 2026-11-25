//go:build cgo

package hiddencode_test

import (
	"context"
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

// loader puts require on the global object and builds a function from a
// decoded string, as a real loader must. Its payload is console.log(1).
const loader = "global['r']=require;(function(){var f=Function(atob('Y29uc29sZS5sb2coMSk='));f();})();\n"

func controlIDs(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ControlID+" "+f.Locus.Path)
	}
	return out
}

func TestDynamicCodeAddedOnlyForAManifestThatTheChangeBringsIn(t *testing.T) {
	root := fstest.MapFS{"jest.config.js": {Data: []byte("module.exports = {};\n" + loader)}}
	both := []string{"dynamic-code jest.config.js", "dynamic-code-added jest.config.js", "dynamic-code jest.config.js"}
	only := []string{"dynamic-code jest.config.js", "dynamic-code jest.config.js"}
	cases := []struct {
		name   string
		change model.Change
		inBase bool
		want   []string
	}{
		{"a full scan has no base", model.ChangeNone, false, only},
		{"an edit of a clean config", model.ChangeModified, false, both},
		{"a new config", model.ChangeAdded, false, both},
		{"a config that had a sign at the base", model.ChangeModified, true, only},
		{"a config that the change keeps", model.ChangeUnchanged, false, only},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "jest.config.js", Kind: model.ManifestKindFile, Change: tc.change, InBase: tc.inBase, Root: root}
			assert.Equal(t, tc.want, controlIDs(plugintest.TestControl(t, c, m, nil)))
		})
	}
}

func TestScriptHookAddedOnlyForAManifestThatTheChangeBringsIn(t *testing.T) {
	root := fstest.MapFS{
		"package.json": {Data: []byte(`{"scripts":{"pretest":"node setup.js"}}`)},
		"setup.js":     {Data: []byte("console.log('setup')\n")},
	}
	cases := []struct {
		name   string
		change model.Change
		inBase bool
		want   []string
	}{
		{"a full scan has no base", model.ChangeNone, false, nil},
		{"the change adds the hook", model.ChangeModified, false, []string{"script-hook-added package.json"}},
		{"the base ran a file with a hook", model.ChangeModified, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "package.json", Kind: model.ManifestKindFile, Change: tc.change, InBase: tc.inBase, Root: root}
			assert.Equal(t, tc.want, controlIDs(plugintest.TestControl(t, c, m, nil)))
		})
	}
}

func TestARoutedFileHasOneOwner(t *testing.T) {
	root := fstest.MapFS{
		"api.js":           {Data: []byte(loader)},
		"a/jest.config.js": {Data: []byte("require('../api');\n")},
		"b/jest.config.js": {Data: []byte("require('../api');\n")},
	}
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	ctx := context.Background()
	manifest := func(id, path string, change model.Change) *model.Manifest {
		return &model.Manifest{ID: id, Path: path, Kind: model.ManifestKindFile, Change: change, Root: root}
	}
	kept := manifest("a", "a/jest.config.js", model.ChangeUnchanged)
	edited := manifest("b", "b/jest.config.js", model.ChangeModified)
	other := manifest("c", "a/jest.config.js", model.ChangeModified)

	got, err := c.Evaluate(ctx, kept, nil)
	require.NoError(t, err)
	assert.Empty(t, got, "pull request mode drops the findings of a kept manifest, so it does not own the file")

	got, err = c.Evaluate(ctx, edited, nil)
	require.NoError(t, err)
	want := []string{"dynamic-code api.js", "dynamic-code-added api.js", "dynamic-code api.js"}
	assert.Equal(t, want, controlIDs(got))

	got, err = c.Evaluate(ctx, other, nil)
	require.NoError(t, err)
	assert.Empty(t, got, "a second config that loads the file does not report it again")

	got, err = c.Evaluate(ctx, edited, nil)
	require.NoError(t, err)
	assert.Equal(t, want, controlIDs(got), "the owner gets its findings again")
}

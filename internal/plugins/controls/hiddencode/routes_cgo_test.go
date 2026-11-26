//go:build cgo

package hiddencode_test

import (
	"context"
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

// loader puts require on the global object and builds a function from a
// decoded string, as a real loader must. Its payload is console.log(1).
const loader = "global['r']=require;(function(){var f=Function(atob('Y29uc29sZS5sb2coMSk='));f();})();\n"

func TestDynamicCodeAddedOnlyForDynamicCodeThatTheBaseDidNotHave(t *testing.T) {
	head := fstest.MapFS{"jest.config.js": {Data: []byte("module.exports = {};\n" + loader)}}
	both := []string{"dynamic-code jest.config.js ADDED", "dynamic-code-added jest.config.js ADDED", "dynamic-code jest.config.js ADDED"}
	only := []string{"dynamic-code jest.config.js", "dynamic-code jest.config.js"}
	cases := []struct {
		name   string
		change model.Change
		base   fstest.MapFS
		want   []string
	}{
		{"a full scan has no base", model.ChangeNone, nil, only},
		{"an edit of a clean config", model.ChangeModified, fstest.MapFS{"jest.config.js": {Data: []byte("module.exports = {};\n")}}, both},
		{"a new config", model.ChangeAdded, fstest.MapFS{}, both},
		{"a config whose base had other dynamic code", model.ChangeModified, fstest.MapFS{"jest.config.js": {Data: []byte("eval(x);\n")}}, both},
		{"a config whose base had the same dynamic code", model.ChangeModified, fstest.MapFS{"jest.config.js": {Data: []byte("// v1\n" + loader)}}, only},
		{"a config that the change keeps", model.ChangeUnchanged, head, only},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "jest.config.js", Kind: model.ManifestKindFile, Change: tc.change, Root: head}
			if tc.base != nil {
				m.Base = tc.base
			}
			assert.Equal(t, tc.want, controlIDs(plugintest.TestControl(t, c, m, nil)))
		})
	}
}

func TestDynamicCodeAddedOnARoutedFile(t *testing.T) {
	head := fstest.MapFS{
		"api.js":         {Data: []byte(loader)},
		"jest.config.js": {Data: []byte("require('./api');\nmodule.exports = {};\n")},
	}
	both := []string{"dynamic-code api.js ADDED", "dynamic-code-added api.js ADDED", "dynamic-code api.js ADDED"}
	only := []string{"dynamic-code api.js", "dynamic-code api.js"}
	cases := []struct {
		name   string
		change model.Change
		base   fstest.MapFS
		want   []string
	}{
		{"the change routes the config to a loader", model.ChangeModified, fstest.MapFS{"api.js": {Data: []byte(loader)}, "jest.config.js": {Data: []byte("module.exports = {};\n")}}, both},
		{"the change puts a loader in a routed file", model.ChangeModified, fstest.MapFS{"api.js": {Data: []byte("module.exports = 1;\n")}, "jest.config.js": {Data: []byte("require('./api');\n")}}, both},
		{"the base routed the config to the same loader", model.ChangeModified, fstest.MapFS{"api.js": {Data: []byte(loader)}, "jest.config.js": {Data: []byte("require('./api');\n")}}, nil},
		{"the change edits only the routed file", model.ChangeUnchanged, fstest.MapFS{"api.js": {Data: []byte("module.exports = 1;\n")}, "jest.config.js": head["jest.config.js"]}, both},
		{"the change edits the routed file and keeps its dynamic code", model.ChangeUnchanged, fstest.MapFS{"api.js": {Data: []byte("// v1\n" + loader)}, "jest.config.js": head["jest.config.js"]}, nil},
		{"a full scan has no base", model.ChangeNone, nil, only},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "jest.config.js", Kind: model.ManifestKindFile, Change: tc.change, Root: head}
			if tc.base != nil {
				m.Base = tc.base
			}
			assert.Equal(t, tc.want, controlIDs(plugintest.TestControl(t, c, m, nil)))
		})
	}
}

func TestDynamicCodeAddedWhenARoutedFileGainsACallOfAKindThatItHad(t *testing.T) {
	old := "module.exports = (s) => new Function('a', s);\n"
	cases := []struct {
		name string
		head string
		want []string
	}{
		{"the change adds a second call", old + "Function(atob('Y29uc29sZS5sb2coMSk='))();\n", []string{"dynamic-code api.js ADDED", "dynamic-code-added api.js ADDED"}},
		{"the change keeps the call", "// v2\n" + old, nil},
		{"the change removes a call", old, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := []byte("require('./api');\n")
			base := old
			if tc.name == "the change removes a call" {
				base = old + "Function(x)();\n"
			}
			c, err := hiddencode.New(plugin.MapConfig(nil))
			require.NoError(t, err)
			m := &model.Manifest{
				ID: "m", Path: "jest.config.js", Kind: model.ManifestKindFile, Change: model.ChangeUnchanged,
				Root: fstest.MapFS{"jest.config.js": {Data: config}, "api.js": {Data: []byte(tc.head)}},
				Base: fstest.MapFS{"jest.config.js": {Data: config}, "api.js": {Data: []byte(base)}},
			}
			assert.Equal(t, tc.want, controlIDs(plugintest.TestControl(t, c, m, nil)))
		})
	}
}

func TestDynamicCodeAddedWhenTheMainOfAPackageRoutesToAnOldLoader(t *testing.T) {
	root := func(main string) fstest.MapFS {
		return fstest.MapFS{
			"jest.config.js":     {Data: []byte("require('./tools');\n")},
			"tools/package.json": {Data: []byte(`{"main":"` + main + `"}`)},
			"tools/a.js":         {Data: []byte("module.exports = 1;\n")},
			"tools/b.js":         {Data: []byte(loader)},
		}
	}
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: "jest.config.js", Kind: model.ManifestKindFile, Change: model.ChangeUnchanged, Root: root("b.js"), Base: root("a.js")}
	assert.Equal(t, []string{"dynamic-code tools/b.js ADDED", "dynamic-code-added tools/b.js ADDED", "dynamic-code tools/b.js ADDED"}, controlIDs(plugintest.TestControl(t, c, m, nil)))
}

func TestARoutedFileGetsTheSameIDsFromEachConfig(t *testing.T) {
	root := fstest.MapFS{
		"api.js":           {Data: []byte(loader)},
		"a/jest.config.js": {Data: []byte("new Function(x)();\nrequire('../api');\n")},
		"b/jest.config.js": {Data: []byte("require('../api');\n")},
	}
	c, err := hiddencode.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	onAPI := func(path string) []string {
		m := &model.Manifest{ID: path, Path: path, Kind: model.ManifestKindFile, Change: model.ChangeAdded, Root: root, Base: fstest.MapFS{}}
		fs, err := c.Evaluate(context.Background(), m, nil)
		require.NoError(t, err)
		var ids []string
		for _, f := range fs {
			if f.Locus.Path == "api.js" {
				ids = append(ids, f.ID)
			}
		}
		return ids
	}
	a := onAPI("a/jest.config.js")
	require.Len(t, a, 3)
	assert.Equal(t, a, onAPI("b/jest.config.js"), "the scan keeps one finding of each id")
}

func controlIDs(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, strings.TrimSpace(f.ControlID+" "+f.Locus.Path+" "+string(f.Change)))
	}
	return out
}

package lockfile

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/packagelockjson"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

const v3 = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    },
    "node_modules/@scope/util": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/@scope/util/-/util-1.0.0.tgz"
    },
    "node_modules/evil": {
      "version": "1.0.0",
      "resolved": "https://evil.example.com/evil/-/evil-1.0.0.tgz"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/not-lodash/-/not-lodash-1.0.0.tgz"
    },
    "node_modules/a/node_modules/internal": {
      "version": "2.0.0",
      "resolved": "https://npm.corp.example/repository/npm/internal/-/internal-2.0.0.tgz"
    },
    "node_modules/strip-ansi-cjs": {
      "version": "6.0.1",
      "resolved": "https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz"
    },
    "node_modules/local": {
      "resolved": "file:../local"
    },
    "node_modules/linked": {
      "resolved": "packages/linked",
      "link": true
    },
    "packages/linked": {
      "version": "0.1.0"
    }
  }
}
`

const v1 = `{
  "name": "old",
  "lockfileVersion": 1,
  "dependencies": {
    "ok": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",
      "dependencies": {
        "nested": {
          "version": "1.0.0",
          "resolved": "http://evil.example.com/nested/-/nested-1.0.0.tgz"
        }
      }
    }
  }
}
`

type hit struct {
	control string
	name    string
	line    int
}

func evaluate(t *testing.T, options plugin.MapConfig, extractor, content string) []hit {
	t.Helper()
	c, err := New(options)
	require.NoError(t, err)
	m := &model.Manifest{
		ID: "m1", Path: "web/package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile,
		Extractor: extractor,
		Root:      fstest.MapFS{"web/package-lock.json": {Data: []byte(content)}},
	}
	var out []hit
	for _, f := range plugintest.TestControl(t, c, m, nil) {
		require.NotNil(t, f.Locus)
		assert.Equal(t, "web/package-lock.json", f.Subject.File.Path)
		out = append(out, hit{control: f.ControlID, name: f.Title, line: f.Locus.StartLine})
	}
	return out
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name      string
		options   plugin.MapConfig
		extractor string
		content   string
		want      []hit
	}{
		{
			name: "lockfile version 3", extractor: packagelockjson.Name, content: v3,
			want: []hit{
				{IDUntrustedRegistry, "internal resolves from an untrusted host", 24},
				{IDPathMismatch, "internal resolves from the URL of another package", 24},
				{IDUntrustedRegistry, "evil resolves from an untrusted host", 16},
				{IDPathMismatch, "lodash resolves from the URL of another package", 20},
			},
		},
		{
			name: "a trusted registry", extractor: packagelockjson.Name, content: v3,
			options: plugin.MapConfig{"trusted_registries": []any{"https://npm.corp.example/repository/npm"}},
			want: []hit{
				{IDUntrustedRegistry, "evil resolves from an untrusted host", 16},
				{IDPathMismatch, "lodash resolves from the URL of another package", 20},
			},
		},
		{
			name: "lockfile version 1", extractor: packagelockjson.Name, content: v1,
			want: []hit{{IDUntrustedRegistry, "nested resolves from an untrusted host", 11}},
		},
		{name: "another extractor", extractor: "python/requirements", content: v3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, evaluate(t, tc.options, tc.extractor, tc.content))
		})
	}
}

func TestEvaluateErrors(t *testing.T) {
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m1", Path: "package-lock.json", Extractor: packagelockjson.Name, Root: fstest.MapFS{}}
	_, err = c.Evaluate(t.Context(), m, nil)
	assert.Error(t, err, "a missing file is an error")

	m.Root = fstest.MapFS{"package-lock.json": {Data: []byte("{")}}
	_, err = c.Evaluate(t.Context(), m, nil)
	assert.Error(t, err, "a file that is not JSON is an error")

	m.Root = nil
	fs, err := c.Evaluate(t.Context(), m, nil)
	require.NoError(t, err)
	assert.Empty(t, fs, "a manifest with no file gives no finding")
}

func TestNewRejectsBadRegistry(t *testing.T) {
	_, err := New(plugin.MapConfig{"trusted_registries": []any{"not a url"}})
	assert.Error(t, err)
}

func TestTrustedSource(t *testing.T) {
	c, err := New(plugin.MapConfig{"trusted_registries": []any{"https://npm.corp.example:8443/npm"}})
	require.NoError(t, err)
	cases := []struct {
		url  string
		want bool
	}{
		{"https://registry.npmjs.org/a/-/a-1.tgz", true},
		{"https://REGISTRY.npmjs.org/a/-/a-1.tgz", true},
		{"http://registry.npmjs.org/a/-/a-1.tgz", false},
		{"https://registry.npmjs.org.evil.com/a/-/a-1.tgz", false},
		{"https://npm.corp.example:8443/npm/a/-/a-1.tgz", true},
		{"https://npm.corp.example/npm/a/-/a-1.tgz", false},
		{"https://npm.corp.example:8443/other/a/-/a-1.tgz", false},
		{"git+ssh://git@github.com:org/repo.git#abc", false},
		{"file:../local", true},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			assert.Equal(t, tc.want, c.(*Control).trustedSource(tc.url))
		})
	}
}

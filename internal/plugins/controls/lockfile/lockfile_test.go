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
    "": {"name": "app", "dependencies": {"left-pad": "^1.3.0"}},
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
	m := &model.Manifest{ID: "m1", Path: "package-lock.json", Kind: model.ManifestKindLockfile, Extractor: packagelockjson.Name, Root: fstest.MapFS{}}
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
			assert.Equal(t, tc.want, c.(*Control).trustedSource(model.EcosystemNpm, tc.url))
		})
	}
}

func TestResolvedEntries(t *testing.T) {
	pkg := func(eco model.Ecosystem, name, version, resolved string) *model.Package {
		return &model.Package{ID: model.MustPackageVersion(eco, name, version), Resolved: resolved}
	}
	cases := []struct {
		name string
		opts map[string]any
		pkg  *model.Package
		want []string
	}{
		{"yarn on the npm registry", nil, pkg(model.EcosystemNpm, "debug", "4.3.4", "https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz#abc"), nil},
		{"yarn on another host", nil, pkg(model.EcosystemNpm, "debug", "4.3.4", "https://evil.example/debug-4.3.4.tgz"), []string{IDUntrustedRegistry}},
		{"yarn on the URL of another package", nil, pkg(model.EcosystemNpm, "debug", "4.3.4", "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"), []string{IDPathMismatch}},
		{"a user registry", map[string]any{"trusted_registries": []any{"https://npm.corp.example"}}, pkg(model.EcosystemNpm, "debug", "4.3.4", "https://npm.corp.example/debug/-/debug-4.3.4.tgz"), nil},
		{"uv on PyPI", nil, pkg(model.EcosystemPyPI, "requests", "2.32.0", "https://pypi.org/simple"), nil},
		{"uv on another index", nil, pkg(model.EcosystemPyPI, "requests", "2.32.0", "https://pypi.evil.example/simple"), []string{IDUntrustedRegistry}},
		{"cargo on crates.io", nil, pkg(model.EcosystemCargo, "serde", "1.0.0", "registry+https://github.com/rust-lang/crates.io-index"), nil},
		{"cargo on the sparse index", nil, pkg(model.EcosystemCargo, "serde", "1.0.0", "sparse+https://index.crates.io/"), nil},
		{"cargo on another registry", nil, pkg(model.EcosystemCargo, "serde", "1.0.0", "registry+https://evil.example/index"), []string{IDUntrustedRegistry}},
		{"a git source is not a registry", nil, pkg(model.EcosystemCargo, "serde", "1.0.0", "git+https://github.com/serde-rs/serde#abc"), nil},
		{"no resolved URL", nil, pkg(model.EcosystemNpm, "debug", "4.3.4", ""), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(plugin.MapConfig(tc.opts))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "yarn.lock", Kind: model.ManifestKindLockfile, Extractor: "javascript/yarnlock", Packages: []*model.Package{tc.pkg}}
			var got []string
			for _, f := range plugintest.TestControl(t, c, m, nil) {
				got = append(got, f.ControlID)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPullRequestChecks(t *testing.T) {
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	m := &model.Manifest{
		ID: "m", Path: "yarn.lock", Kind: model.ManifestKindLockfile, Extractor: "javascript/yarnlock", Ecosystem: model.EcosystemNpm,
		LockfileOnly: true, Change: model.ChangeModified,
		Packages: []*model.Package{
			{ID: model.MustPackageVersion(model.EcosystemNpm, "debug", "4.3.4"), Change: model.ChangeModified, Integrity: "sha512-new", PreviousIntegrity: "sha512-old"},
			{ID: model.MustPackageVersion(model.EcosystemNpm, "ms", "2.1.3"), Change: model.ChangeUnchanged, Integrity: "sha512-same"},
			{ID: model.MustPackageVersion(model.EcosystemNpm, "chalk", "5.3.0"), Change: model.ChangeModified, PreviousIntegrity: "sha512-gone"},
			{
				ID: model.MustPackageVersion(model.EcosystemNpm, "lodash", "4.17.21"), Change: model.ChangeModified,
				Integrity: "sha512-kept", PreviousIntegrity: "sha512-kept",
				Resolved:         "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				PreviousResolved: "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz",
			},
		},
	}
	byID := map[string]int{}
	for _, f := range plugintest.TestControl(t, c, m, nil) {
		byID[f.ControlID]++
	}
	assert.Equal(t, map[string]int{IDIntegrityChanged: 2, IDLockfileOnly: 1}, byID, "a changed or removed hash, not a URL change with the same hash")
}

func TestInstalledNotLocked(t *testing.T) {
	npmPkg := func(name, version string) *model.Package {
		return &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, name, version)}
	}
	lock := &model.Manifest{
		ID: "lock", Path: "app/package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile,
		Extractor: packagelockjson.Name,
		Packages:  []*model.Package{npmPkg("left-pad", "1.3.0"), npmPkg("minimist", "1.2.8"), npmPkg("bundled", "1.0.0")},
	}
	// The extractor drops the git dependency, because it has no npm PURL.
	root := fstest.MapFS{"app/package-lock.json": {Data: []byte(`{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
  "node_modules/minimist": {"version": "1.2.8", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz"},
  "node_modules/from-git": {"version": "2.0.0", "resolved": "git+ssh://git@github.com/o/from-git.git#abc"},
  "node_modules/bundled": {"version": "1.0.0", "inBundle": true}
}}`)}}
	installed := func(p string, pkg *model.Package) *model.Manifest {
		return &model.Manifest{ID: p, Path: p, Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindInstalled, Root: root, Packages: []*model.Package{pkg}}
	}
	cases := []struct {
		name  string
		m     *model.Manifest
		title string
	}{
		{"locked", installed("app/node_modules/left-pad/package.json", npmPkg("left-pad", "1.3.0")), ""},
		{"other version", installed("app/node_modules/minimist/package.json", npmPkg("minimist", "1.2.0")), "npm/minimist@1.2.0 is installed, and the lockfile has 1.2.8"},
		{"not listed", installed("app/node_modules/a/node_modules/evil/package.json", npmPkg("evil", "1.0.0")), "npm/evil@1.0.0 is installed, and the lockfile does not list it"},
		{"no lockfile in the project", installed("other/node_modules/evil/package.json", npmPkg("evil", "1.0.0")), ""},
		{"git dependency", installed("app/node_modules/from-git/package.json", npmPkg("from-git", "2.0.0")), ""},
		{"no resolved field", installed("app/node_modules/bundled/package.json", npmPkg("bundled", "2.0.0")), "npm/bundled@2.0.0 is installed, and the lockfile has 1.0.0"},
		{"workspace member", installed("app/packages/a/node_modules/evil/package.json", npmPkg("evil", "1.0.0")), "npm/evil@1.0.0 is installed, and the lockfile does not list it"},
	}
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := plugintest.NewMemState(lock, tc.m)
			fs := plugintest.TestControl(t, c, tc.m, s)
			if tc.title == "" {
				assert.Empty(t, fs)
				return
			}
			require.Len(t, fs, 1)
			assert.Equal(t, IDInstalledNotLocked, fs[0].ControlID)
			assert.Equal(t, tc.title, fs[0].Title)
		})
	}
}

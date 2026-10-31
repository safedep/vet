package codeusage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

// pythonVenv writes a virtual environment under dir with the distributions
// of a site-packages directory, and a fake interpreter with a standard
// library under interp. It returns the site-packages directory.
func pythonVenv(t *testing.T, dir, interp, name string) string {
	t.Helper()
	home := filepath.Join(interp, "bin")
	mkfile(t, filepath.Join(interp, "lib", "python3.12", "os.py"), "")
	mkfile(t, filepath.Join(dir, name, "pyvenv.cfg"), "home = "+home+"\nversion_info = 3.12.3.final.0\n")
	site := filepath.Join(dir, name, "lib", "python3.12", "site-packages")
	mkfile(t, filepath.Join(site, "requests-2.31.0.dist-info", "METADATA"), "Name: requests\nVersion: 2.31.0\n")
	mkfile(t, filepath.Join(site, "requests-2.31.0.dist-info", "RECORD"), "requests/__init__.py,,\nrequests/api.py,,\n")
	mkfile(t, filepath.Join(site, "requests", "__init__.py"), "from . import api\n")
	mkfile(t, filepath.Join(site, "requests", "api.py"), "import urllib3\n")
	mkfile(t, filepath.Join(site, "urllib3-2.0.7.dist-info", "METADATA"), "Name: urllib3\nVersion: 2.0.7\n")
	mkfile(t, filepath.Join(site, "urllib3-2.0.7.dist-info", "RECORD"), "urllib3/__init__.py,,\n")
	mkfile(t, filepath.Join(site, "urllib3", "__init__.py"), "import socket\n")
	mkfile(t, filepath.Join(site, "google_auth-2.0.0.dist-info", "METADATA"), "Name: google-auth\nVersion: 2.0.0\n")
	mkfile(t, filepath.Join(site, "google_auth-2.0.0.dist-info", "RECORD"), "google/auth/__init__.py,,\ngoogle/oauth2/__init__.py,,\n")
	mkfile(t, filepath.Join(site, "google", "auth", "__init__.py"), "")
	mkfile(t, filepath.Join(site, "google", "oauth2", "__init__.py"), "")
	mkfile(t, filepath.Join(site, "app-0.1.0.dist-info", "METADATA"), "Name: app\nVersion: 0.1.0\n")
	mkfile(t, filepath.Join(site, "app-0.1.0.dist-info", "direct_url.json"), `{"url": "file:///app", "dir_info": {"editable": true}}`)
	mkfile(t, filepath.Join(site, "app-0.1.0.dist-info", "RECORD"), "app/__init__.py,,\n")
	mkfile(t, filepath.Join(site, "six-1.16.0.dist-info", "METADATA"), "Name: six\nVersion: 1.16.0\n")
	mkfile(t, filepath.Join(site, "six-1.16.0.dist-info", "top_level.txt"), "six\n")
	mkfile(t, filepath.Join(site, "six.py"), "")
	mkfile(t, filepath.Join(site, "fast-1.0.0.dist-info", "METADATA"), "Name: fast\nVersion: 1.0.0\n")
	mkfile(t, filepath.Join(site, "fast-1.0.0.dist-info", "RECORD"), "fast.cpython-312-x86_64-linux-gnu.so,,\n")
	return site
}

func TestPythonEnvironmentUnits(t *testing.T) {
	dir, interp := t.TempDir(), t.TempDir()
	site := pythonVenv(t, dir, interp, ".venv")
	t.Setenv("VIRTUAL_ENV", "")
	env := readPythonEnvironment(dir)
	require.Len(t, env.sites, 1)
	assert.Equal(t, filepath.Join(interp, "lib", "python3.12"), env.stdlib)
	assert.Equal(t, "3.12.3", env.version)

	cases := []struct {
		name string
		id   model.PackageVersion
		want Unit
	}{
		{"a distribution at the version of the manifest", model.MustPackageVersion(model.EcosystemPyPI, "Requests", "2.31.0"), Unit{Key: "pypi:requests@2.31.0", Root: site, Dir: filepath.Join(site, "requests")}},
		{"another version", model.MustPackageVersion(model.EcosystemPyPI, "requests", "2.30.0"), Unit{}},
		{"a namespace package gives each of its packages", model.MustPackageVersion(model.EcosystemPyPI, "google_auth", "2.0.0"), Unit{Key: "pypi:google-auth@2.0.0", Root: site, Dir: filepath.Join(site, "google", "auth"), Dirs: []string{filepath.Join(site, "google", "oauth2")}}},
		{"an editable install is the project", model.MustPackageVersion(model.EcosystemPyPI, "app", "0.1.0"), Unit{}},
		{"a module with top_level.txt and no RECORD", model.MustPackageVersion(model.EcosystemPyPI, "six", "1.16.0"), Unit{Key: "pypi:six@1.16.0", Root: site, Dir: filepath.Join(site, "six.py")}},
		{"a distribution with no Python file", model.MustPackageVersion(model.EcosystemPyPI, "fast", "1.0.0"), Unit{}},
		{"a distribution that is not installed", model.MustPackageVersion(model.EcosystemPyPI, "django", "4.2.0"), Unit{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, ok := env.unit(c.id)
			assert.Equal(t, c.want.Key != "", ok)
			assert.Equal(t, c.want, u)
		})
	}
	std, ok := env.stdlibUnit()
	require.True(t, ok)
	assert.Equal(t, Unit{Key: "python:std@3.12.3", Dir: filepath.Join(interp, "lib", "python3.12")}, std)
}

func TestPythonEnvironmentFindsEachEnvironment(t *testing.T) {
	t.Run("VIRTUAL_ENV first, then the directories of the target", func(t *testing.T) {
		dir, outside, interp := t.TempDir(), t.TempDir(), t.TempDir()
		pythonVenv(t, dir, interp, "venv")
		active := pythonVenv(t, outside, interp, "active")
		t.Setenv("VIRTUAL_ENV", filepath.Join(outside, "active"))
		env := readPythonEnvironment(dir)
		require.Len(t, env.sites, 2)
		assert.Equal(t, active, env.sites[0].dir)
		assert.Equal(t, filepath.Join(dir, "venv", "lib", "python3.12", "site-packages"), env.sites[1].dir)
	})
	t.Run("a Windows layout", func(t *testing.T) {
		dir, interp := t.TempDir(), t.TempDir()
		t.Setenv("VIRTUAL_ENV", "")
		mkfile(t, filepath.Join(interp, "Lib", "os.py"), "")
		mkfile(t, filepath.Join(dir, ".venv", "pyvenv.cfg"), "home = "+interp+"\nversion = 3.12.3\n")
		mkfile(t, filepath.Join(dir, ".venv", "Lib", "site-packages", "six-1.16.0.dist-info", "METADATA"), "Name: six\nVersion: 1.16.0\n")
		mkfile(t, filepath.Join(dir, ".venv", "Lib", "site-packages", "six-1.16.0.dist-info", "top_level.txt"), "six\n../../escape\n")
		mkfile(t, filepath.Join(dir, ".venv", "Lib", "site-packages", "six.py"), "")
		mkfile(t, filepath.Join(dir, "escape.py"), "")
		env := readPythonEnvironment(dir)
		require.Len(t, env.sites, 1)
		assert.Equal(t, filepath.Join(dir, ".venv", "Lib", "site-packages"), env.sites[0].dir)
		assert.Equal(t, filepath.Join(interp, "Lib"), env.stdlib, "the library is under the home of python.exe")
		u, ok := env.unit(model.MustPackageVersion(model.EcosystemPyPI, "six", "1.16.0"))
		require.True(t, ok)
		assert.Equal(t, filepath.Join(env.sites[0].dir, "six.py"), u.Dir)
		assert.Empty(t, u.Dirs, "a name of top_level.txt that leaves site-packages is no directory of the unit")
	})
	t.Run("a directory with no pyvenv.cfg is no environment", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("VIRTUAL_ENV", "")
		mkfile(t, filepath.Join(dir, ".venv", "lib", "python3.12", "site-packages", "six.py"), "")
		assert.Empty(t, readPythonEnvironment(dir).sites)
	})
}

func TestPythonVersion(t *testing.T) {
	for in, want := range map[string]string{"3.12.3": "3.12.3", "3.12.3.final.0": "3.12.3", "3.13": "3.13", "3": "", "3.x.1": ""} {
		assert.Equal(t, want, pythonVersion(in), in)
	}
}

func TestEnricherUnitOfReadsThePythonEnvironmentOnce(t *testing.T) {
	dir := t.TempDir()
	site := pythonVenv(t, dir, t.TempDir(), ".venv")
	t.Setenv("VIRTUAL_ENV", "")
	e := NewWith(dir, Options{}, nil)
	u, ok := e.unitOf(model.MustPackageVersion(model.EcosystemPyPI, "requests", "2.31.0"))
	require.True(t, ok)
	assert.Equal(t, filepath.Join(site, "requests"), u.Dir)
	_, ok = e.unitOf(model.MustPackageVersion(model.EcosystemGo, "example.com/none", "1.0.0"))
	assert.False(t, ok)
}

func TestReachQueryAddsTheStandardLibraryForAPythonUnit(t *testing.T) {
	dir := t.TempDir()
	pythonVenv(t, dir, t.TempDir(), ".venv")
	t.Setenv("VIRTUAL_ENV", "")
	record := []model.SymbolRecord{{Keys: []string{"requests//api//get"}, FixSites: []string{"requests.api.get"}}}
	imported := &model.Usage{Imported: true, Symbols: record}
	requests := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "requests", "2.31.0"), Enrichment: model.Enrichment{Usage: imported}}
	django := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "django", "4.2.0"), Enrichment: model.Enrichment{Usage: imported}}
	e := NewWith(dir, Options{}, nil)
	q, hasUnit := e.reachQuery([]*model.Package{requests, django})
	var keys []string
	for _, u := range q.Units {
		keys = append(keys, u.Key)
	}
	assert.Equal(t, []string{"pypi:requests@2.31.0", "python:std@3.12.3"}, keys, "the standard library joins the code of a Python dependency")
	assert.True(t, hasUnit[requests.ID.Key()])
	assert.False(t, hasUnit[django.ID.Key()], "django is not installed")
	assert.Equal(t, []string{"django"}, e.noCode[model.EcosystemPyPI])

	e = NewWith(t.TempDir(), Options{}, nil)
	goPkg := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/none", "1.0.0"), Enrichment: model.Enrichment{Usage: imported}}
	q, _ = e.reachQuery([]*model.Package{goPkg})
	assert.Empty(t, q.Units, "a Go package with no code adds no Python unit")
}

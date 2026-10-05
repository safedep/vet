package extractors

import (
	"io/fs"
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/githubactions"
	"github.com/safedep/vet/v2/internal/plugins/extractors/installed"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile"
	"github.com/safedep/vet/v2/internal/plugins/extractors/packagejson"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/plugins/extractors/terraform"
	"github.com/safedep/vet/v2/model"
)

type named struct {
	filesystem.Extractor
	name string
}

func (n named) Name() string { return n.name }

func TestOverride(t *testing.T) {
	a, b, c := named{name: "a"}, named{name: "b"}, named{name: "c"}
	b2 := named{name: "b"}
	got := Override([]filesystem.Extractor{a, b}, b2, c)
	require.Len(t, got, 3)
	assert.Equal(t, []filesystem.Extractor{a, b2, c}, got)
}

func TestDefaultUsesTheVetLockfileExtractors(t *testing.T) {
	exs, err := Default()
	require.NoError(t, err)
	vet, err := lockfile.Extractors()
	require.NoError(t, err)

	byName := map[string]filesystem.Extractor{}
	for _, e := range exs {
		_, dup := byName[e.Name()]
		assert.False(t, dup, "extractor %s is in the set twice", e.Name())
		byName[e.Name()] = e
	}
	for _, v := range vet {
		assert.IsType(t, v, byName[v.Name()], "the set must use the vet copy of %s", v.Name())
	}
	assert.IsType(t, &githubactions.Extractor{}, byName[githubactions.Name])
	assert.Contains(t, byName, terraform.Name)
	assert.Contains(t, byName, packagejson.Name)
}

func TestFor(t *testing.T) {
	stat := func(p string) filesystem.FileAPI { return simplefileapi.New(p, fakeInfo{}) }
	cases := []struct {
		packages  model.Packages
		installed bool
		declared  bool
	}{
		{model.PackagesDeclared, false, true},
		{model.PackagesInstalled, true, false},
		{model.PackagesAll, true, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.packages), func(t *testing.T) {
			exs, err := For(tc.packages)
			require.NoError(t, err)
			assert.Equal(t, tc.installed, slices.ContainsFunc(exs, scalibr.ReadsInstalled))
			reads := func(p string) bool {
				return slices.ContainsFunc(exs, func(e filesystem.Extractor) bool { return e.FileRequired(stat(p)) })
			}
			assert.Equal(t, tc.declared, reads("package-lock.json"))
			assert.Equal(t, tc.installed, reads("node_modules/left-pad/package.json"))
			assert.False(t, reads("node_modules/left-pad/package-lock.json"), "a declared extractor must not read a file of an installed package")
			assert.False(t, reads("usr/lib/python3/dist-packages/x/requirements.txt"))
		})
	}
	_, err := For("everything")
	assert.Error(t, err)
}

// Each installed extractor must give manifests of kind installed, so the
// engine walks node_modules and the report names the origin.
func TestInstalledExtractorsReadInstalled(t *testing.T) {
	exs, err := installed.Extractors()
	require.NoError(t, err)
	for _, e := range exs {
		assert.True(t, scalibr.ReadsInstalled(e), e.Name())
	}
}

type fakeInfo struct{ fs.FileInfo }

func (fakeInfo) Size() int64       { return 10 }
func (fakeInfo) IsDir() bool       { return false }
func (fakeInfo) Mode() fs.FileMode { return 0o644 }

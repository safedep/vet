package extractors

import (
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/githubactions"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile"
	"github.com/safedep/vet/v2/internal/plugins/extractors/packagejson"
	"github.com/safedep/vet/v2/internal/plugins/extractors/terraform"
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

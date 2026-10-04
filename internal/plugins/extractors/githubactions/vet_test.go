package githubactions_test

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/githubactions"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

// TestVetCompositeActionsAndSubpaths checks that a subpath is not part of
// the package identity. github/codeql-action/init and
// github/codeql-action/analyze are the same package, and advisories name it
// github/codeql-action.
func TestVetCompositeActionsAndSubpaths(t *testing.T) {
	e, err := githubactions.New(nil)
	require.NoError(t, err)
	exs := []filesystem.Extractor{e}

	cases := []struct {
		path string
		want []string
	}{
		{".github/actions/setup/action.yml", []string{"github-actions/actions/setup-go@v5", "github-actions/github/codeql-action@v3"}},
		{".github/workflows/ci.yml", []string{
			"github-actions/actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
			"github-actions/github/codeql-action@v3",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/repo", Path: tc.path}, exs)
			require.Empty(t, errs)
			require.Len(t, ms, 1)
			var got []string
			for _, p := range ms[0].Packages {
				got = append(got, p.ID.String())
			}
			assert.Equal(t, tc.want, got)
			assert.Equal(t, "workflow", string(ms[0].Kind))
		})
	}
}

func TestVetFileRequired(t *testing.T) {
	e, err := githubactions.New(nil)
	require.NoError(t, err)
	cases := map[string]bool{
		".github/workflows/ci.yml":            true,
		".github/actions/setup/action.yml":    true,
		"sub/.github/actions/x/y/action.yaml": true,
		".github/actions/setup/README.md":     false,
		"action.yml":                          false,
		".github/actions/setup/other.yml":     false,
	}
	for p, want := range cases {
		assert.Equal(t, want, e.FileRequired(simplefileapi.New(p, fakeInfo{})), p)
	}
}

package pyproject

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

func TestRequirement(t *testing.T) {
	cases := []struct {
		in, name, version string
		ok                bool
	}{
		{"requests[socks]>=2.31,<3", "requests", "", true},
		{"click==8.1.7 ; python_version >= '3.9'", "click", "8.1.7", true},
		{"attrs~=23.1", "attrs", "", true},
		{"six===1.16.0", "six", "1.16.0", true},
		{"django<5", "django", "", true},
		{"rich", "rich", "", true},
		{"numpy (==1.26.4)", "numpy", "1.26.4", true},
		{"pkg==1.2.*", "pkg", "", true},
		{"mylib @ git+https://github.com/example/mylib", "", "", false},
	}
	for _, tc := range cases {
		name, version, ok := Requirement(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.name, name, tc.in)
		assert.Equal(t, tc.version, version, tc.in)
	}
}

func TestExtract(t *testing.T) {
	exs := []filesystem.Extractor{New()}
	cases := []struct {
		dir  string
		want map[string]bool
	}{
		{"pep621", map[string]bool{
			"pypi/requests": false, "pypi/click@8.1.7": false, "pypi/rich": false, "pypi/attrs": false,
			"pypi/django": false, "pypi/httpx": false, "pypi/pytest": true, "pypi/ruff@0.6.9": true,
		}},
		{"poetry", map[string]bool{
			"pypi/fastapi": false, "pypi/uvicorn": false, "pypi/anything": false, "pypi/pytest": true, "pypi/pydantic@2.7.1": false,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/" + tc.dir, Path: "pyproject.toml"}, exs)
			require.Empty(t, errs)
			require.Len(t, ms, 1)
			got := map[string]bool{}
			for _, p := range ms[0].Packages {
				got[p.ID.String()] = p.Dev
			}
			assert.Equal(t, tc.want, got, "no project itself, no URL or path dependency")
		})
	}
	ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/locked", Path: "pyproject.toml"}, exs)
	require.Empty(t, errs)
	assert.Empty(t, ms, "the lockfile wins")
}

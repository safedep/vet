package scalibr

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/model"
)

// goldenManifest is the stable view of a manifest for a golden file.
type goldenManifest struct {
	Manifest *model.Manifest  `json:"manifest"`
	Packages []*model.Package `json:"packages"`
	Roots    []string         `json:"roots,omitempty"`
	Edges    []string         `json:"edges,omitempty"`
	Errors   []string         `json:"errors,omitempty"`
}

func view(ms []*model.Manifest, errs []error) []goldenManifest {
	var out []goldenManifest
	for _, m := range ms {
		g := goldenManifest{Manifest: m, Packages: m.Packages}
		if m.Graph != nil {
			for _, r := range m.Graph.Roots() {
				g.Roots = append(g.Roots, r.String())
			}
			m.Graph.Edges(func(p, c model.PackageID) { g.Edges = append(g.Edges, p.String()+" -> "+c.String()) })
			sort.Strings(g.Edges)
		}
		out = append(out, g)
	}
	if len(out) == 0 {
		out = append(out, goldenManifest{})
	}
	for _, e := range errs {
		out[0].Errors = append(out[0].Errors, e.Error())
	}
	return out
}

func TestExtractFileGolden(t *testing.T) {
	exs, err := SourceExtractors()
	require.NoError(t, err)

	cases := []struct {
		dir, file string
		kind      model.ManifestKind
	}{
		{"npm", "package-lock.json", model.ManifestKindLockfile},
		{"npm-optional", "package-lock.json", model.ManifestKindLockfile},
		{"go", "go.mod", model.ManifestKindLockfile},
		{"pip", "requirements.txt", model.ManifestKindManifest},
		{"cargo", "Cargo.lock", model.ManifestKindLockfile},
		{"cdx", "bom.cdx.json", model.ManifestKindSBOM},
		{"gha", ".github/workflows/ci.yml", model.ManifestKindWorkflow},
		{"conan", "conan.lock", ""},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			ms, errs := ExtractFile(context.Background(), File{Root: filepath.Join("testdata", tc.dir), Path: tc.file}, exs)
			golden.AssertJSON(t, filepath.Join("testdata", "golden", tc.dir+".json"), view(ms, errs))
			if tc.kind == "" {
				assert.Empty(t, ms, "no vet ecosystem")
				assert.NotEmpty(t, errs)
				return
			}
			require.Len(t, ms, 1)
			m := ms[0]
			assert.Equal(t, tc.kind, m.Kind)
			assert.Equal(t, model.ManifestID(tc.file, m.Extractor), m.ID)
			assert.NotEmpty(t, m.Packages)
			b, err := fs.ReadFile(m.Root, m.Path)
			require.NoError(t, err)
			assert.NotEmpty(t, b)
		})
	}
}

func TestManifestsAreDirect(t *testing.T) {
	exs, err := SourceExtractors()
	require.NoError(t, err)
	ms, _ := ExtractFile(context.Background(), File{Root: "testdata/pip", Path: "requirements.txt"}, exs)
	require.Len(t, ms, 1)
	for _, p := range ms[0].Packages {
		assert.True(t, p.Direct, p.ID.String())
	}
}

func TestSourceExtractors(t *testing.T) {
	exs, err := SourceExtractors()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, e := range exs {
		names[e.Name()] = true
	}
	for name := range lockfiles {
		assert.True(t, names[name], "lockfile extractor %s is not in the source set", name)
	}
	for name := range excluded {
		assert.False(t, names[name], "%s must stay out of the source set", name)
	}
	assert.True(t, names["github/actions"])
	assert.True(t, names["java/archive"])
}

func TestKindOf(t *testing.T) {
	assert.Equal(t, model.ManifestKindLockfile, kindOf("javascript/packagelockjson"))
	assert.Equal(t, model.ManifestKindSBOM, kindOf("sbom/spdx"))
	assert.Equal(t, model.ManifestKindWorkflow, kindOf("github/actions"))
	assert.Equal(t, model.ManifestKindManifest, kindOf("python/requirements"))
}

func TestWorkflowWithNoAction(t *testing.T) {
	exs, err := SourceExtractors()
	require.NoError(t, err)
	file := ".github/workflows/greet.yml"
	ms, errs := ExtractFile(context.Background(), File{Root: "testdata/gha-run-only", Path: file}, exs)
	require.Empty(t, errs)
	require.Len(t, ms, 1, "a workflow is a manifest with no package, for the workflow controls")
	assert.Equal(t, model.ManifestKindWorkflow, ms[0].Kind)
	assert.Equal(t, model.EcosystemGitHubActions, ms[0].Ecosystem)
	assert.Empty(t, ms[0].Packages)

	// The upstream extractor accepts a file that is not YAML, such as a
	// template, with no error. The workflow controls skip it too.
	ms, errs = ExtractFile(context.Background(), File{Root: "testdata/gha-invalid", Path: ".github/workflows/broken.yml"}, exs)
	assert.Empty(t, errs)
	require.Len(t, ms, 1)
	assert.Empty(t, ms[0].Packages)
}

func TestGoLocalReplaceIsNotAPackage(t *testing.T) {
	exs, err := SourceExtractors()
	require.NoError(t, err)
	ms, errs := ExtractFile(context.Background(), File{Root: "testdata/gomod-replace", Path: "go.mod"}, exs)
	assert.Empty(t, errs, "a replace with a local path is project code, not an error")
	require.Len(t, ms, 1)
	var names []string
	for _, p := range ms[0].Packages {
		names = append(names, p.ID.QualifiedName()+"@"+p.ID.Version)
	}
	assert.Contains(t, names, "github.com/me/forked@1.0.1")
	assert.NotContains(t, names, "../sdk@")
	for _, n := range names {
		assert.NotContains(t, n, "acme/sdk", "the local replacement drops the module")
	}
}

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/plugin"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestPolicies(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "vet-policy.yml")
	write(t, one, "version: 2\n")
	write(t, filepath.Join(dir, "policies", "b.yaml"), "version: 2\n")
	write(t, filepath.Join(dir, "policies", "a.yml"), "version: 2\n")
	write(t, filepath.Join(dir, "policies", "notes.txt"), "x")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "policies", "sub.yml"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "empty"), 0o755))

	cases := []struct {
		name    string
		path    string
		want    []string
		wantErr bool
	}{
		{name: "a file", path: one, want: []string{one}},
		{name: "a directory with a trailing separator", path: filepath.Join(dir, "policies") + string(filepath.Separator), want: []string{filepath.Join(dir, "policies", "a.yml"), filepath.Join(dir, "policies", "b.yaml")}},
		{name: "a directory", path: filepath.Join(dir, "policies"), want: []string{filepath.Join(dir, "policies", "a.yml"), filepath.Join(dir, "policies", "b.yaml")}},
		{name: "a missing file", path: filepath.Join(dir, "nope.yml"), wantErr: true},
		{name: "a directory with no policy", path: filepath.Join(dir, "empty"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			docs, err := New(tc.path).Policies(context.Background())
			if tc.wantErr {
				ue, ok := usefulerror.AsUsefulError(err)
				require.True(t, ok)
				assert.Equal(t, policy.CodeInvalid, ue.Code())
				return
			}
			require.NoError(t, err)
			var names []string
			for _, d := range docs {
				names = append(names, d.Name)
				assert.NotEmpty(t, d.Content)
			}
			assert.Equal(t, tc.want, names)
		})
	}
}

func TestEvaluatorFromTheSource(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.yml"), "version: 2\nrules:\n  - id: r1\n    when: 'true'\n    action: warn\n")
	write(t, filepath.Join(dir, "b.yml"), "version: 2\nrules:\n  - id: r2\n    when: 'true'\n    action: fail\n")
	e, err := policy.NewFromSources(context.Background(), policy.Options{}, New(dir))
	require.NoError(t, err)
	assert.True(t, e.Gated())

	write(t, filepath.Join(dir, "c.yml"), "version: 2\nrules:\n  - id: r1\n    when: 'true'\n    action: fail\n")
	_, err = policy.NewFromSources(context.Background(), policy.Options{}, New(dir))
	assert.ErrorContains(t, err, `rule "r1" is also in`)
}

func TestFactory(t *testing.T) {
	src, err := Factory(plugin.MapConfig{"path": "p.yml"})
	require.NoError(t, err)
	assert.Equal(t, "p.yml", src.(*Source).name)

	Register()
	reg, err := plugin.NewPolicySource(Name, plugin.MapConfig{"path": "p.yml"})
	require.NoError(t, err)
	assert.IsType(t, &Source{}, reg)

	_, err = Factory(plugin.MapConfig(nil))
	assert.Error(t, err)
	_, err = Factory(plugin.MapConfig{"url": "x"})
	assert.Error(t, err)
}

func TestNewFSLabelsTheDocs(t *testing.T) {
	fsys := fstest.MapFS{
		".github/vet/policy.yml": {Data: []byte("version: 2\n")},
		"policies/a.yml":         {Data: []byte("version: 2\n")},
	}
	label := func(name string) string { return "origin/main:" + name }

	docs, err := NewFS(fsys, ".github/vet/policy.yml", label).Policies(context.Background())
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "origin/main:.github/vet/policy.yml", docs[0].Name)

	docs, err = NewFS(fsys, "policies", label).Policies(context.Background())
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "origin/main:policies/a.yml", docs[0].Name)

	_, err = NewFS(fsys, "missing.yml", label).Policies(context.Background())
	assert.ErrorContains(t, err, "origin/main:missing.yml")
}

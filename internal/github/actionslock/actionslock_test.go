package actionslock

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lockText = `version: 'v0.0.3'
workflows:
    '.github/workflows/ci.yml':
        - 'acme/build@v1.2.0'
        - 'acme/cache@v4'
        - 'acme/remote@v3'
    '.github/workflows/empty.yml': []
dependencies:
    'acme/build@v1.2.0':
        ref: 'v1.2.0'
        commit: 'sha1-1111111111111111111111111111111111111111'
        owner_id: 101
        repo_id: 201
    'acme/cache@v4':
        ref: 'v4'
        commit: 'sha1-2222222222222222222222222222222222222222'
        owner_id: 101
        repo_id: 202
    'acme/remote@v3':
        hostname: 'acme.ghe.com'
        ref: 'v3'
        commit: 'sha256-4444444444444444444444444444444444444444444444444444444444444444'
        owner_id: 101
        repo_id: 204
`

func TestLocks(t *testing.T) {
	l, err := Parse([]byte(lockText))
	require.NoError(t, err)
	tests := []struct {
		name     string
		workflow string
		uses     string
		want     bool
	}{
		{"locked tag", ".github/workflows/ci.yml", "acme/build@v1.2.0", true},
		{"owner and repo in another case", ".github/workflows/ci.yml", "ACME/Build@v1.2.0", true},
		{"sub-path of a locked action", ".github/workflows/cache.yml", "acme/cache/save@v4", false},
		{"sub-path in a listed workflow", ".github/workflows/ci.yml", "acme/cache/save@v4", true},
		{"ref in another case", ".github/workflows/ci.yml", "acme/build@V1.2.0", false},
		{"other ref of a locked action", ".github/workflows/ci.yml", "acme/build@v1", false},
		{"entry of another host", ".github/workflows/ci.yml", "acme/remote@v3", false},
		{"workflow that the lockfile does not list", ".github/workflows/other.yml", "acme/build@v1.2.0", false},
		{"listed workflow with no entries", ".github/workflows/empty.yml", "acme/build@v1.2.0", false},
		{"workflow path in another case", ".github/workflows/CI.yml", "acme/build@v1.2.0", false},
		{"reusable workflow of a locked repository", ".github/workflows/ci.yml", "acme/build/.github/workflows/x.yml@v1.2.0", false},
		{"docker image", ".github/workflows/ci.yml", "docker://acme/build:v1.2.0", false},
		{"local action", ".github/workflows/ci.yml", "./acme/build", false},
		{"expression", ".github/workflows/ci.yml", "acme/build@${{ inputs.ref }}", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, l.Locks(tt.workflow, tt.uses))
		})
	}
}

func TestLists(t *testing.T) {
	l, err := Parse([]byte(lockText))
	require.NoError(t, err)
	assert.True(t, l.Lists(".github/workflows/ci.yml"))
	assert.True(t, l.Lists(".github/workflows/empty.yml"))
	assert.False(t, l.Lists(".github/workflows/other.yml"))

	var none *Lock
	assert.False(t, none.Lists(".github/workflows/ci.yml"))
	assert.False(t, none.Locks(".github/workflows/ci.yml", "acme/build@v1.2.0"))
	assert.Empty(t, none.Locked(".github/workflows/ci.yml"))
}

func TestCoverage(t *testing.T) {
	l, err := Parse([]byte(lockText))
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{".github/workflows/ci.yml": {"acme/build@v1.2.0", "acme/cache@v4"}}, l.Coverage())
	var none *Lock
	assert.Empty(t, none.Coverage())
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"older version", strings.Replace(lockText, "v0.0.3", "v0.0.2", 1)},
		{"newer version", strings.Replace(lockText, "v0.0.3", "v1.0.0", 1)},
		{"unknown key", lockText + "extra: true\n"},
		{"entry whose ref is not the ref of its key", strings.Replace(lockText, "ref: 'v4'", "ref: 'v5'", 1)},
		{"duplicate key", lockText + strings.Join(strings.Split(lockText, "\n")[9:14], "\n") + "\n"},
		{"commit that is not a digest", strings.Replace(lockText, "sha1-1111111111111111111111111111111111111111", "1111111111111111111111111111111111111111", 1)},
		{"missing repository id", strings.Replace(lockText, "        repo_id: 201\n", "", 1)},
		{"not YAML", "version: ["},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.text))
			assert.Error(t, err)
		})
	}
}

func TestRead(t *testing.T) {
	tests := []struct {
		name    string
		fsys    fstest.MapFS
		root    string
		want    bool
		wantErr bool
	}{
		{"lockfile at the root", fstest.MapFS{".github/workflows/actions.lock": {Data: []byte(lockText)}}, ".", true, false},
		{"lockfile of a nested repository", fstest.MapFS{"sub/.github/workflows/actions.lock": {Data: []byte(lockText)}}, "sub", true, false},
		{"no workflows folder", fstest.MapFS{"README.md": {}}, ".", false, false},
		{"no lockfile", fstest.MapFS{".github/workflows/ci.yml": {}}, ".", false, false},
		{"name in another case", fstest.MapFS{".github/workflows/Actions.lock": {Data: []byte(lockText)}}, ".", false, false},
		{"link", fstest.MapFS{".github/workflows/actions.lock": {Data: []byte("x"), Mode: fs.ModeSymlink}}, ".", false, false},
		{"file that is not valid", fstest.MapFS{".github/workflows/actions.lock": {Data: []byte("version: v0.0.3\nextra: 1\n")}}, ".", false, true},
		{"file that is too large", fstest.MapFS{".github/workflows/actions.lock": {Data: make([]byte, 1<<20+1)}}, ".", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := Read(tt.fsys, tt.root)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, l != nil)
		})
	}
}

func TestWorkflow(t *testing.T) {
	tests := []struct {
		path     string
		wantRoot string
		wantKey  string
		wantOK   bool
	}{
		{".github/workflows/ci.yml", ".", ".github/workflows/ci.yml", true},
		{"sub/dir/.github/workflows/ci.yml", "sub/dir", ".github/workflows/ci.yml", true},
		{".github/workflows/nested/ci.yml", "", "", false},
		{".github/actions/build/action.yml", "", "", false},
		{".github/workflows/actions.lock", "", "", false},
		{"my.github/workflows/ci.yml", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			root, key, ok := Workflow(tt.path)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRoot, root)
			assert.Equal(t, tt.wantKey, key)
		})
	}
	for p, want := range map[string]string{".github/workflows/actions.lock": ".", "sub/.github/workflows/actions.lock": "sub"} {
		root, ok := Lockfile(p)
		assert.True(t, ok, p)
		assert.Equal(t, want, root, p)
	}
	for _, p := range []string{".github/actions.lock", ".github/workflows/ci.yml", ".github/workflows/x/actions.lock"} {
		_, ok := Lockfile(p)
		assert.False(t, ok, p)
	}
}

func TestEnforced(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"", true},
		{"https://api.github.com", true},
		{"https://API.GitHub.com/", true},
		{"https://api.acme.ghe.com", true},
		{"https://github.acme.internal/api/v3", false},
		{"https://api.github.com.evil.example", false},
		{"://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, Enforced(tt.url))
		})
	}
}

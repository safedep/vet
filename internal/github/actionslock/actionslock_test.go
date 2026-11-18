package actionslock

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/github/actionslock/actionslocktest"
)

var sample = actionslocktest.Lock{
	Workflows: map[string][]string{
		".github/workflows/ci.yml":    {"acme/build@v1.2.0", "acme/cache@v4", "acme/remote@v3"},
		".github/workflows/empty.yml": {},
	},
	Hosts: map[string]string{"acme/remote@v3": "acme.ghe.com"},
}

func TestStatus(t *testing.T) {
	l, err := Parse([]byte(sample.String()))
	require.NoError(t, err)
	tests := []struct {
		name     string
		workflow string
		uses     string
		want     Status
	}{
		{"locked tag", ".github/workflows/ci.yml", "acme/build@v1.2.0", Locked},
		{"owner and repo in another case", ".github/workflows/ci.yml", "ACME/Build@v1.2.0", Locked},
		{"sub-path of a locked action", ".github/workflows/ci.yml", "acme/cache/save@v4", Locked},
		{"ref in another case", ".github/workflows/ci.yml", "acme/build@V1.2.0", Missing},
		{"other ref of a locked action", ".github/workflows/ci.yml", "acme/build@v1", Missing},
		{"entry of another host", ".github/workflows/ci.yml", "acme/remote@v3", Missing},
		{"listed workflow with no entries", ".github/workflows/empty.yml", "acme/build@v1.2.0", Missing},
		{"workflow that the lockfile does not list", ".github/workflows/other.yml", "acme/build@v1.2.0", Unlisted},
		{"workflow key in another case", ".github/workflows/CI.yml", "acme/build@v1.2.0", Unlisted},
		{"reusable workflow of a locked repository", ".github/workflows/ci.yml", "acme/build/.github/workflows/x.yml@v1.2.0", Unlisted},
		{"docker image", ".github/workflows/ci.yml", "docker://acme/build:v1.2.0", Unlisted},
		{"local action", ".github/workflows/ci.yml", "./acme/build", Unlisted},
		{"expression", ".github/workflows/ci.yml", "acme/build@${{ inputs.ref }}", Unlisted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, l.Workflow(tt.workflow).Status(tt.uses))
		})
	}
	var none *Lock
	assert.Equal(t, Unlisted, none.Workflow(".github/workflows/ci.yml").Status("acme/build@v1.2.0"))
	assert.False(t, none.Workflow(".github/workflows/ci.yml").Listed())
	assert.True(t, l.Workflow(".github/workflows/empty.yml").Listed())
}

func TestCoverage(t *testing.T) {
	l, err := Parse([]byte(sample.String()))
	require.NoError(t, err)
	base := l.Coverage()
	assert.Equal(t, Coverage{".github/workflows/ci.yml": {"acme/build@v1.2.0", "acme/cache@v4"}}, base)

	var none *Lock
	tests := []struct {
		name string
		head Coverage
		want []string
	}{
		{"same", base, nil},
		{"lockfile removed", none.Coverage(), []string{".github/workflows/ci.yml"}},
		{"key removed", Coverage{".github/workflows/ci.yml": {"acme/cache@v4"}}, []string{".github/workflows/ci.yml"}},
		{"key added", Coverage{".github/workflows/ci.yml": {"acme/build@v1.2.0", "acme/cache@v4", "acme/new@v1"}}, nil},
		{"key replaced", Coverage{".github/workflows/ci.yml": {"acme/build@v1.2.0", "acme/new@v1"}}, []string{".github/workflows/ci.yml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, base.Lost(tt.head))
		})
	}
}

func TestParseRejects(t *testing.T) {
	// A hostname needs schema v0.0.3, so the version cases use a file with
	// none. vet then refuses the file only for its version.
	text := actionslocktest.Lock{Workflows: sample.Workflows}.String()
	_, err := Parse([]byte(text))
	require.NoError(t, err)
	var many strings.Builder
	many.WriteString("version: 'v0.0.3'\nworkflows:\n")
	for i := range maxKeys + 1 {
		fmt.Fprintf(&many, "  'w%d': []\n", i)
	}
	tests := []struct {
		name string
		text string
	}{
		{"older version", strings.Replace(text, "v0.0.3", "v0.0.2", 1)},
		{"newer version", strings.Replace(text, "v0.0.3", "v1.0.0", 1)},
		{"mapping with too many keys", many.String()},
		{"file that is too large", strings.Repeat(" ", MaxSize+1)},
		{"entry that is not valid", text + "extra: true\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.text))
			assert.Error(t, err)
		})
	}
}

func TestRead(t *testing.T) {
	text := []byte(sample.String())
	tests := []struct {
		name    string
		fsys    fstest.MapFS
		root    string
		want    bool
		wantErr bool
	}{
		{"lockfile at the root", fstest.MapFS{".github/workflows/actions.lock": {Data: text}}, ".", true, false},
		{"lockfile of a nested repository", fstest.MapFS{"sub/.github/workflows/actions.lock": {Data: text}}, "sub", true, false},
		{"no workflows folder", fstest.MapFS{"README.md": {}}, ".", false, false},
		{"no lockfile", fstest.MapFS{".github/workflows/ci.yml": {}}, ".", false, false},
		{"name in another case", fstest.MapFS{".github/workflows/Actions.lock": {Data: text}}, ".", false, false},
		{"link", fstest.MapFS{".github/workflows/actions.lock": {Data: text, Mode: fs.ModeSymlink}}, ".", false, false},
		{"file that is not valid", fstest.MapFS{".github/workflows/actions.lock": {Data: []byte("version: v0.0.3\nextra: 1\n")}}, ".", false, true},
		{"file that is too large", fstest.MapFS{".github/workflows/actions.lock": {Data: make([]byte, MaxSize+1)}}, ".", false, true},
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

func TestWorkflowKey(t *testing.T) {
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
			root, key, ok := WorkflowKey(tt.path)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRoot, root)
			assert.Equal(t, tt.wantKey, key)
		})
	}
}

func TestLockfileRoot(t *testing.T) {
	tests := []struct {
		path     string
		wantRoot string
		wantOK   bool
	}{
		{".github/workflows/actions.lock", ".", true},
		{"sub/.github/workflows/actions.lock", "sub", true},
		{".github/actions.lock", "", false},
		{".github/workflows/x/actions.lock", "", false},
		{".github/workflows/ci.yml", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			root, ok := LockfileRoot(tt.path)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRoot, root)
		})
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
		{"https://api.github.com@evil.example", false},
		{"https://api.evilghe.com", false},
		{"://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, Enforced(tt.url))
		})
	}
}

func TestCacheParsesEachContentOnce(t *testing.T) {
	text := []byte(sample.String())
	fsys := fstest.MapFS{
		"a/.github/workflows/actions.lock": {Data: text},
		"b/.github/workflows/actions.lock": {Data: text},
		"c/.github/workflows/actions.lock": {Data: []byte(actionslocktest.Lock{Workflows: map[string][]string{".github/workflows/x.yml": {"acme/x@v1"}}}.String())},
	}
	var c Cache
	a, err := c.Read(fsys, "a")
	require.NoError(t, err)
	b, err := c.Read(fsys, "b")
	require.NoError(t, err)
	other, err := c.Read(fsys, "c")
	require.NoError(t, err)
	assert.Same(t, a, b, "the same content gives the kept parse")
	assert.NotSame(t, a, other)
}

func TestActionRoot(t *testing.T) {
	tests := []struct {
		path     string
		wantRoot string
		wantDir  string
		wantOK   bool
	}{
		{".github/actions/build/action.yml", ".", ".github/actions/build", true},
		{"sub/.github/actions/build/action.yaml", "sub", ".github/actions/build", true},
		{".github/actions/build/notes.yml", "", "", false},
		{"tools/build/action.yml", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			root, dir, ok := ActionRoot(tt.path)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRoot, root)
			assert.Equal(t, tt.wantDir, dir)
		})
	}
}

func TestCallersAndWorkflows(t *testing.T) {
	lock := actionslocktest.Lock{Workflows: map[string][]string{
		".github/workflows/a.yml": {"acme/build@v1", "acme/test@v1"},
		".github/workflows/b.yml": {"acme/build@v1"},
	}}
	l, err := Parse([]byte(lock.String()))
	require.NoError(t, err)
	step := func(uses string) string { return "jobs:\n  j:\n    steps:\n      - uses: " + uses + "\n" }
	fsys := fstest.MapFS{
		".github/workflows/a.yml":             {Data: []byte(step("./.github/actions/outer"))},
		".github/workflows/b.yml":             {Data: []byte(step("$/.github/actions/inner"))},
		".github/workflows/c.yml":             {Data: []byte(step("./.github/actions/unused"))},
		".github/actions/outer/action.yml":    {Data: []byte("runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n    - uses: ./../escape\n")},
		".github/actions/inner/action.yaml":   {Data: []byte("runs:\n  using: composite\n  steps:\n    - uses: acme/build@v1\n")},
		".github/actions/unused/action.yml":   {Data: []byte("runs:\n  using: composite\n  steps:\n    - uses: acme/build@v1\n")},
		".github/workflows/actions.lock":      {Data: []byte(lock.String())},
		".github/actions/outer/extra/x.yml":   {},
		".github/actions/inner/action.yml.bk": {},
	}
	callers := l.Callers(fsys, ".")
	assert.Equal(t, map[string][]string{
		".github/actions/outer": {".github/workflows/a.yml"},
		".github/actions/inner": {".github/workflows/a.yml", ".github/workflows/b.yml"},
	}, callers, "an unlisted workflow and a path out of the repository give no caller")

	inner := l.Workflows(callers[".github/actions/inner"])
	assert.True(t, inner.Listed())
	assert.Equal(t, Locked, inner.Status("acme/build@v1"))
	assert.Equal(t, Missing, inner.Status("acme/test@v1"), "b.yml does not lock it")
	assert.False(t, l.Workflows(callers[".github/actions/unused"]).Listed())
}

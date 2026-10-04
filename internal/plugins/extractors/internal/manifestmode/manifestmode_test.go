package manifestmode

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocked(t *testing.T) {
	fsys := fstest.MapFS{
		"Cargo.lock":                 {},
		"crates/core/Cargo.toml":     {},
		"apps/web/package-lock.json": {},
		"apps/web/package.json":      {},
		"apps/api/package.json":      {},
	}
	cases := []struct {
		dir   string
		names []string
		want  bool
	}{
		{"crates/core", []string{"Cargo.lock"}, true},
		{".", []string{"Cargo.lock"}, true},
		{"apps/web", []string{"package-lock.json"}, true},
		{"apps/api", []string{"package-lock.json"}, false},
		{"apps/api", []string{"yarn.lock"}, false},
	}
	for _, tc := range cases {
		got, err := Locked(fsys, tc.dir, tc.names)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got, tc.dir)
	}
}

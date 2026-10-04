package state

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOneFileManager keeps RejectNetworkFS on every open of a state file.
func TestOneFileManager(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var users []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		if strings.Contains(string(b), "localdb.NewFileManager(") || strings.Contains(string(b), "localdb.New(") {
			users = append(users, f)
		}
	}
	assert.Equal(t, []string{"localdb.go"}, users)
}

func TestStateFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no permission bits")
	}
	s := openStore(t)
	_, e := newScan(t, s, "/a")
	for _, p := range []string{s.Index().Path(), e.File} {
		info, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), p)
	}
}

package state

import (
	"os"
	"path/filepath"
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

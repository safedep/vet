package lockfile_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(to, b, 0o600))
}

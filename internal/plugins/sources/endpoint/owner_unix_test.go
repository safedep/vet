//go:build !windows

package endpoint

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/report"
)

func TestHomeUser(t *testing.T) {
	me, err := user.Current()
	require.NoError(t, err)
	home := t.TempDir()

	assert.Equal(t, &report.InventoryUser{Name: me.Username, UID: strconv.Itoa(os.Getuid())}, homeUser(home),
		"the owner of the directory is the user")

	missing := filepath.Join(home, "gone")
	assert.Equal(t, &report.InventoryUser{Name: "gone"}, homeUser(missing),
		"a directory that vet cannot read gives its name")
}

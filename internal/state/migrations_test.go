package state

import (
	"context"
	"testing"

	"github.com/safedep/dry/localdb"
	"github.com/stretchr/testify/require"
)

// TestScanMigrationsAppend opens a scan file of the schema before the
// indexes. localdb applies the migrations after the count that the file
// holds, so a new statement must go at the end of the list.
func TestScanMigrationsAppend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	old := scanMigrations[:len(scanMigrations)-2]

	mgr, err := openFile(dir, "s.db")
	require.NoError(t, err)
	_, err = mgr.Store(ctx, localdb.Descriptor{Name: "vet_scan", Migrations: old})
	require.NoError(t, err)
	require.NoError(t, mgr.Close())

	mgr, err = openFile(dir, "s.db")
	require.NoError(t, err)
	_, err = mgr.Store(ctx, localdb.Descriptor{Name: "vet_scan", Migrations: scanMigrations})
	require.NoError(t, err)
	require.NoError(t, mgr.Close())
}

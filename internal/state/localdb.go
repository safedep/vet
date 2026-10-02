package state

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/safedep/dry/localdb"
)

// openFile is the only place that makes a localdb file manager, so every
// state file rejects a network file system. It creates a new file with
// mode 0600 first, because SQLite creates it with the umask, and the WAL
// and SHM files take the mode of the database file.
func openFile(dir, name string) (localdb.FileManager, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		if err := f.Close(); err != nil {
			return nil, err
		}
	case !errors.Is(err, fs.ErrExist) && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return localdb.NewFileManager(localdb.Config{Dir: dir, FileName: name, RejectNetworkFS: true}), nil
}

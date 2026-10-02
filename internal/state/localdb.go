package state

import "github.com/safedep/dry/localdb"

// openFile is the only place that makes a localdb file manager, so every
// state file rejects a network file system.
func openFile(dir, name string) localdb.FileManager {
	return localdb.NewFileManager(localdb.Config{Dir: dir, FileName: name, RejectNetworkFS: true})
}

package engine

import (
	"path/filepath"

	"github.com/safedep/vet/v2/plugin"
)

// rootSystemDirs are the directories under a file system root that hold no
// packages: kernel and device trees, and the macOS system volumes that
// repeat the data volume.
var rootSystemDirs = map[string]bool{"proc": true, "sys": true, "dev": true, "System/Volumes": true}

// systemDirs returns the test for the directories that the walk of an
// artifact does not enter: a pseudo file system, or a system directory
// under a file system root.
func systemDirs(a plugin.Artifact) func(rel string) bool {
	none := func(string) bool { return false }
	if a.Kind != plugin.ArtifactDirectory || a.Path == "" {
		return none
	}
	abs, err := filepath.Abs(a.Path)
	if err != nil {
		return none
	}
	root := filepath.Dir(abs) == abs
	return func(rel string) bool {
		return (root && rootSystemDirs[rel]) || pseudoFS(filepath.Join(abs, filepath.FromSlash(rel)))
	}
}

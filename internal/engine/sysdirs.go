package engine

import (
	"path/filepath"
	"strings"

	"github.com/safedep/vet/v2/plugin"
)

// rootSystemDirs are the directories under a file system root that hold no
// packages: kernel and device trees, and the macOS system volumes that
// repeat the data volume.
var rootSystemDirs = map[string]bool{"proc": true, "sys": true, "dev": true, "System/Volumes": true}

// systemDirs returns the test for the directories that the walk of an
// artifact does not enter: a pseudo file system, or a system directory
// under a file system root. "." tests the target itself, which can be on
// a pseudo file system too.
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
	mounts := pseudoMounts()
	return func(rel string) bool {
		if rel == "." {
			return under(abs, mounts)
		}
		return (root && rootSystemDirs[rel]) || mounts[filepath.Join(abs, filepath.FromSlash(rel))]
	}
}

// under reports a path at or under one of the mount points.
func under(p string, mounts map[string]bool) bool {
	for m := range mounts {
		if p == m || strings.HasPrefix(p, strings.TrimSuffix(m, string(filepath.Separator))+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

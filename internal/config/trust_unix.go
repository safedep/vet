//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
)

// ManagedFileTrusted reports whether root owns the managed file and every
// directory above it, and no one else can write them.
func ManagedFileTrusted(path string) bool {
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for {
		st, err := os.Stat(p)
		if err != nil {
			return false
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 {
			return false
		}
		if st.Mode().Perm()&0o022 != 0 && st.Mode()&os.ModeSticky == 0 {
			return false
		}
		parent := filepath.Dir(p)
		if parent == p {
			return true
		}
		p = parent
	}
}

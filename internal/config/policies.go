package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// PolicyDir returns the directory of the named policies. vet policy init
// writes to it.
func (r *Runtime) PolicyDir() string { return filepath.Join(r.Dirs.Config, "policies") }

// PolicyFile returns the file of a policy name: PolicyDir/NAME.yml.
func (r *Runtime) PolicyFile(name string) string {
	return filepath.Join(r.PolicyDir(), name+".yml")
}

// ResolvePolicy returns the policy file that a --policy value or the
// policy.file key names. A policy name names a file in PolicyDir, unless a
// file or directory with that name is in the current directory.
func (r *Runtime) ResolvePolicy(s string) string {
	if !IsPolicyName(s) {
		return s
	}
	if _, err := os.Stat(s); !errors.Is(err, fs.ErrNotExist) {
		return s
	}
	return r.PolicyFile(s)
}

// IsPolicyName reports whether s is a policy name and not a path: it has
// no path separator and no extension.
func IsPolicyName(s string) bool {
	return s != "" && filepath.Ext(s) == "" && !strings.ContainsAny(s, `/\`)
}

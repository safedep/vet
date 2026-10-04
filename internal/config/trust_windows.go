//go:build windows

package config

// ManagedFileTrusted accepts the managed file on Windows. Only an
// administrator can write %ProgramData%\safedep\vet by default.
//
// Known gap: vet does not read the file's ACL. An administrator who loosens
// the ACL of the directory also loosens this check.
func ManagedFileTrusted(string) bool { return true }

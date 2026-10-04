// Package version holds the build version of vet. The release build sets
// version and commit with -ldflags "-X".
package version

import "runtime/debug"

var (
	version string
	commit  string
)

// Version returns the release version, or the module version of a "go
// install" build, or "devel".
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "devel"
}

// Commit returns the commit of the build, or an empty string.
func Commit() string {
	if commit != "" {
		return commit
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

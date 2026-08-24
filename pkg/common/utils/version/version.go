// Package version tells a release apart from a version expression that names a
// set of releases.
package version

import "strings"

// SPDX writes these when it has no version to give. A report must not carry
// either one as a release.
var unresolved = map[string]bool{
	"NOASSERTION": true,
	"NONE":        true,
}

const (
	operatorChars = "<>=!~^"
	// A release identifier holds none of these. Each one either starts another
	// clause of a version expression or stands for any release.
	rejectChars = "<>=!~^*|, \t"
)

// Resolve returns the release that expr names, and an empty string when expr
// names a set of releases instead of one.
//
// vet's malware and insights lookups key on one exact release, so a caller must
// not fall back to the floor of a range: the 2.28 of ">=2.28" names a release
// the manifest never asked for, and a lookup against it reads as clean.
func Resolve(expr string) string {
	expr = strings.TrimSpace(expr)

	release := strings.TrimLeft(expr, operatorChars)
	if operator := expr[:len(expr)-len(release)]; strings.Trim(operator, "=") != "" {
		return ""
	}

	release = strings.TrimSpace(release)
	if unresolved[release] || strings.ContainsAny(release, rejectChars) {
		return ""
	}

	return release
}

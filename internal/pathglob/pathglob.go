// Package pathglob matches a slash path of a target against a pattern of
// scan.exclude or of a policy suppression, so that both read a pattern the
// same way.
package pathglob

import (
	"path"
	"strings"
)

// Match reports whether p matches pattern: the whole path, its base name,
// a folder of the path, or the base name of a folder, as test/fixtures for
// test/fixtures/a/b.js and fixtures for src/fixtures/x.js. The scan walk
// tests each folder on the way down, so a pattern matches the same files
// here and in scan.exclude. A pattern uses the syntax of path.Match. A
// trailing /** names a folder, as in test/fixtures/**. A finding with no
// file has no path, and no pattern matches it.
func Match(pattern, p string) bool {
	if p == "" {
		return false
	}
	pattern = strings.TrimSuffix(strings.TrimSuffix(pattern, "/**"), "/")
	for q := p; q != "." && q != "/"; q = path.Dir(q) {
		if ok, _ := path.Match(pattern, q); ok {
			return true
		}
		if ok, _ := path.Match(pattern, path.Base(q)); ok {
			return true
		}
	}
	return false
}

// Valid reports whether pattern has the syntax of path.Match, with / to
// cut the folders. path.Match reads a backslash as an escape, so
// test\fixtures matches testfixtures and hides nothing. A ** matches one
// folder only, so it is valid only as a trailing /**.
func Valid(pattern string) bool {
	if strings.Contains(pattern, `\`) || strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
		return false
	}
	_, err := path.Match(pattern, "")
	return err == nil
}

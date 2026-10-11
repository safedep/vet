// Package pathglob matches a slash path of a target against a pattern of
// scan.exclude or of a policy suppression, so that both read a pattern the
// same way.
package pathglob

import (
	"path"
	"strings"
)

// Match reports whether p matches pattern: the whole path, its base name,
// or a folder of the path, as test/fixtures for test/fixtures/a/b.js. A
// pattern uses the syntax of path.Match. A trailing /** names the folder,
// as in test/fixtures/**.
func Match(pattern, p string) bool {
	pattern = strings.TrimSuffix(strings.TrimSuffix(pattern, "/**"), "/")
	if ok, _ := path.Match(pattern, p); ok {
		return true
	}
	if ok, _ := path.Match(pattern, path.Base(p)); ok {
		return true
	}
	return strings.HasPrefix(p, pattern+"/")
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

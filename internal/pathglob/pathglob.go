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
// pattern uses the syntax of path.Match.
func Match(pattern, p string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	if ok, _ := path.Match(pattern, p); ok {
		return true
	}
	if ok, _ := path.Match(pattern, path.Base(p)); ok {
		return true
	}
	return strings.HasPrefix(p, pattern+"/")
}

// Valid reports whether pattern has the syntax of path.Match.
func Valid(pattern string) bool {
	_, err := path.Match(pattern, "")
	return err == nil
}

// Package version reads a best-effort version out of a version expression.
package version

import "strings"

const (
	// A leading run of these introduces a bound or a range, never a release.
	operatorChars = "<>=!~^([ "
	// Each one of these separates the clauses of a multi-clause expression.
	clauseSeparators = ",| \t"
)

// BestEffort returns the version that expr names, or the lowest version it
// bounds. vet chooses coverage over accuracy here: the package name carries
// most of the security signal, and a package vet drops carries none, so the
// caller gets an approximate version rather than nothing.
//
// The result is empty only when expr names no version at all.
func BestEffort(expr string) string {
	clauses := strings.FieldsFunc(strings.TrimLeft(strings.TrimSpace(expr), operatorChars),
		func(r rune) bool { return strings.ContainsRune(clauseSeparators, r) })

	if len(clauses) == 0 {
		return ""
	}

	return clauses[0]
}

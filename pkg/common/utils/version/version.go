// Package version reads a best-effort version out of a version expression.
package version

import (
	"strings"
	"unicode"
)

const (
	// A leading run of these introduces a bound or a range, never a release.
	operatorChars = "<>=!~^(["
	// These separate the clauses of a multi-clause expression. Whitespace
	// separates them too, so a clause never holds any.
	clauseSeparators = ",|"
)

// BestEffort returns the version that expr names, or the lowest version it
// bounds. vet chooses coverage over accuracy here: the package name carries
// most of the security signal, and a package vet drops carries none, so the
// caller gets an approximate version rather than nothing.
//
// The result is empty only when expr names no version at all.
func BestEffort(expr string) string {
	for _, clause := range strings.FieldsFunc(expr, isClauseBreak) {
		if release := strings.TrimLeft(clause, operatorChars); release != "" {
			return release
		}
	}

	return ""
}

func isClauseBreak(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(clauseSeparators, r)
}

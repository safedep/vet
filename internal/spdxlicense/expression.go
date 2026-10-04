package spdxlicense

import (
	"slices"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// The SPDX values of a license field that are not license expressions.
const (
	noAssertion = "NOASSERTION"
	none        = "NONE"
)

// Declared is the license of a package, from its declared license values.
type Declared struct {
	// Expression joins the values that parse with AND. SPDX and CycloneDX
	// do not define a list of declared licenses, and AND is the stricter
	// reading. It is empty when no value parses.
	Expression string
	// IDs reports that each value is one active SPDX license id.
	IDs bool
	// Unknown holds the values that do not parse, and NOASSERTION.
	Unknown []string
	// None reports a NONE value: the package has no license.
	None bool
}

// Parse reads the declared license values of a package. A package with no
// value has an unknown license.
func Parse(values []string) Declared {
	d := Declared{IDs: true}
	var terms []string
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		switch {
		case v == "":
			continue
		case strings.EqualFold(v, none):
			d.None = true
			continue
		case strings.EqualFold(v, noAssertion):
			d.Unknown = append(d.Unknown, v)
			continue
		}
		if id, ok := ActiveID(v); ok {
			terms = append(terms, id)
			continue
		}
		d.IDs = false
		if _, err := spdxexp.ExtractLicenses(v); err != nil {
			d.Unknown = append(d.Unknown, v)
			continue
		}
		terms = append(terms, "("+v+")")
	}
	switch len(terms) {
	case 0:
		d.IDs = false
	case 1:
		d.Expression = strings.TrimSuffix(strings.TrimPrefix(terms[0], "("), ")")
	default:
		d.Expression = strings.Join(terms, " AND ")
	}
	d.Unknown = slices.Compact(d.Unknown)
	return d
}

// Known reports a license that a check can decide: an expression with no
// unknown value, or NONE.
func (d Declared) Known() bool {
	return len(d.Unknown) == 0 && (d.Expression != "" || d.None)
}

// ActiveID returns the active SPDX license id of v, in the case of the SPDX
// License List, or false when v is not one active id.
func ActiveID(v string) (string, bool) {
	ok, id := spdxexp.ActiveLicense(strings.TrimSpace(v))
	return id, ok
}

// maxEqualTerms bounds the terms that Equal compares by meaning. It
// evaluates each subset of the terms, so the cost doubles with each term.
const maxEqualTerms = 8

// Equal reports whether two lists of declared license values mean the same
// license. "MIT OR Apache-2.0" equals "Apache-2.0 OR MIT", and GPL-3.0 equals
// GPL-3.0-only. Two expressions are equal when they name the same terms and
// the same sets of licenses satisfy both. The term check keeps GPL-2.0-only
// apart from GPL-2.0-or-later, which go-spdx lets satisfy each other. Values
// that do not parse compare as sorted strings.
func Equal(a, b []string) bool {
	x, y := Parse(a), Parse(b)
	if !x.Known() || !y.Known() || x.None || y.None {
		return sortedEqual(a, b)
	}
	tx, errX := spdxexp.ExtractLicenses(x.Expression)
	ty, errY := spdxexp.ExtractLicenses(y.Expression)
	if errX != nil || errY != nil {
		return sortedEqual(a, b)
	}
	if !slices.Equal(termKeys(tx), termKeys(ty)) {
		return false
	}
	terms := slices.Compact(slices.Sorted(slices.Values(append(tx, ty...))))
	if len(terms) > maxEqualTerms {
		return sortedEqual(a, b)
	}
	for mask := 1; mask < 1<<len(terms); mask++ {
		var allowed []string
		for i, t := range terms {
			if mask&(1<<i) != 0 {
				allowed = append(allowed, t)
			}
		}
		sx, errX := spdxexp.Satisfies(x.Expression, allowed)
		sy, errY := spdxexp.Satisfies(y.Expression, allowed)
		if errX != nil || errY != nil || sx != sy {
			return false
		}
	}
	return true
}

func sortedEqual(a, b []string) bool {
	x, y := slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b))
	return slices.Equal(x, y)
}

func termKeys(terms []string) []string {
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		out = append(out, termKey(t))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

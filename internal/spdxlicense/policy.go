package spdxlicense

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// Verdict is the result of a license check.
type Verdict string

// The verdicts of a license check.
const (
	Pass       Verdict = "pass"
	Denied     Verdict = "denied"
	NotAllowed Verdict = "not-allowed"
	Unknown    Verdict = "unknown"
)

// Policy holds an allow list and a deny list. Each entry is an SPDX license
// id, an "id WITH exception" term, a LicenseRef or the name of a set.
type Policy struct {
	allow []string
	deny  map[string]bool
}

// NewPolicy checks each entry and expands the sets. An entry that is not a
// valid SPDX term is an error, so a typo cannot open the gate.
func NewPolicy(allow, deny []string) (*Policy, error) {
	a, err := expand(allow)
	if err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	d, err := expand(deny)
	if err != nil {
		return nil, fmt.Errorf("deny: %w", err)
	}
	p := &Policy{allow: a, deny: map[string]bool{}}
	for _, e := range d {
		p.deny[termKey(e)] = true
	}
	return p, nil
}

// Allows reports whether the policy has an allow list.
func (p *Policy) Allows() bool { return len(p.allow) > 0 }

// Denies reports whether the policy has a deny list.
func (p *Policy) Denies() bool { return len(p.deny) > 0 }

// Result is the verdict of a check, with the denied terms of a Denied
// verdict.
type Result struct {
	Verdict Verdict
	Denied  []string
}

// Check applies the deny list, then the allow list. A license that has a
// choice with no denied term is not denied, so "MIT OR GPL-3.0-only" passes
// a deny list with GPL-3.0-only. A license that the check cannot decide is
// Unknown, unless a denied term already decides it.
func (p *Policy) Check(d Declared) (Result, error) {
	if d.Expression != "" && p.Denies() {
		denied, err := p.denied(d.Expression)
		if err != nil {
			return Result{}, err
		}
		if len(denied) > 0 {
			return Result{Verdict: Denied, Denied: denied}, nil
		}
	}
	if !d.Known() {
		return Result{Verdict: Unknown}, nil
	}
	if !p.Allows() {
		return Result{Verdict: Pass}, nil
	}
	if d.None {
		return Result{Verdict: NotAllowed}, nil
	}
	ok, err := spdxexp.Satisfies(d.Expression, p.allow)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Verdict: NotAllowed}, nil
	}
	return Result{Verdict: Pass}, nil
}

// denied returns the denied terms of an expression when no choice of the
// expression avoids them, else nil. A kept term that satisfies a denied
// term, such as GPL-2.0-or-later for a denied GPL-2.0-only, does not avoid
// it: the check takes the stricter reading.
func (p *Policy) denied(expr string) ([]string, error) {
	terms, err := spdxexp.ExtractLicenses(expr)
	if err != nil {
		return nil, err
	}
	var denied, keep []string
	for _, t := range terms {
		if p.deny[termKey(t)] {
			denied = append(denied, t)
		}
	}
	if len(denied) == 0 {
		return nil, nil
	}
	for _, t := range terms {
		if p.deny[termKey(t)] {
			continue
		}
		covers := false
		for _, d := range denied {
			if ok, err := spdxexp.Satisfies(d, []string{t}); err == nil && ok {
				covers = true
				break
			}
		}
		if !covers {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		return denied, nil
	}
	ok, err := spdxexp.Satisfies(expr, keep)
	if err != nil || ok {
		return nil, err
	}
	return denied, nil
}

// expand checks the entries and replaces each set with its ids.
func expand(entries []string) ([]string, error) {
	var out, bad []string
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if ids, ok := setIDs(e); ok {
			out = append(out, ids...)
			continue
		}
		if !validTerm(e) {
			bad = append(bad, raw)
			continue
		}
		out = append(out, e)
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%q: %w", bad, errInvalidEntry)
	}
	return slices.Compact(out), nil
}

var errInvalidEntry = errors.New("not an SPDX license id, an id WITH an exception, a LicenseRef or a set (" + strings.Join(Sets, ", ") + ")")

// validTerm accepts one license term: an id, "id+", "id WITH exception" or
// a LicenseRef. It rejects an expression with OR or AND.
func validTerm(e string) bool {
	f := strings.Fields(e)
	if len(f) != 1 && (len(f) != 3 || !strings.EqualFold(f[1], "WITH")) {
		return false
	}
	terms, err := spdxexp.ExtractLicenses(e)
	return err == nil && len(terms) == 1
}

// termKey is the key of a term for the deny list: its SPDX form in lower
// case, with a deprecated id mapped to its successor.
func termKey(t string) string {
	if terms, err := spdxexp.ExtractLicenses(t); err == nil && len(terms) == 1 {
		t = terms[0]
	}
	base, exception, with := strings.Cut(t, " WITH ")
	base = strings.ToLower(strings.TrimSpace(base))
	if r, ok := replacement[base]; ok {
		base = strings.ToLower(r)
	}
	if with {
		return base + " with " + strings.ToLower(strings.TrimSpace(exception))
	}
	return base
}

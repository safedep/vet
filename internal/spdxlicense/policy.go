package spdxlicense

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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
// id, an "id WITH exception" term, a LicenseRef or the name of a set. An
// entry matches a term of the same canonical form only: GPL-2.0-only does
// not match GPL-2.0-only WITH Classpath-exception-2.0.
type Policy struct {
	allow map[string]bool
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
	return &Policy{allow: a, deny: d}, nil
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
// a deny list with GPL-3.0-only. With both lists, one choice must satisfy
// both: "GPL-3.0-only OR SSPL-1.0" fails allow [GPL-3.0-only, MIT] with deny
// [GPL-3.0-only]. The values join with AND, so a known value that fails a
// list fails the package, whatever its unknown values are. NONE alone fails
// an allow list. A deny list alone cannot decide it, so it is unknown.
func (p *Policy) Check(d Declared) Result {
	if d.root != nil && p.Denies() && p.denied(d.root) {
		return Result{Verdict: Denied, Denied: p.deniedTerms(d.root)}
	}
	if p.Allows() && (d.None || d.root != nil && !p.allowed(d.root)) {
		return Result{Verdict: NotAllowed}
	}
	if !d.Known() || d.NoLicense() {
		return Result{Verdict: Unknown}
	}
	return Result{Verdict: Pass}
}

// restrictive holds the licenses that limit the use of the code: source
// available, no commercial use or no derived works. The SPDX License List
// has no flag for them.
var restrictive = sync.OnceValue(func() *Policy {
	deny := []string{"SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0"}
	for id, l := range ids {
		if !l.Deprecated && (strings.HasPrefix(id, "cc-by-nc") || strings.HasPrefix(id, "cc-by-nd")) {
			deny = append(deny, l.ID)
		}
	}
	p, err := NewPolicy(nil, deny)
	if err != nil {
		panic(err)
	}
	return p
})

// Restricted reports that each choice of the license has a license that
// limits the use of the code, such as SSPL-1.0, BUSL-1.1 or CC-BY-NC-4.0.
func Restricted(d Declared) bool {
	return d.root != nil && restrictive().denied(d.root)
}

// allowed reports whether a choice of the expression has only terms that
// the allow list names and the deny list does not.
func (p *Policy) allowed(n *node) bool {
	switch n.op {
	case opAnd:
		for _, k := range n.kids {
			if !p.allowed(k) {
				return false
			}
		}
		return true
	case opOr:
		return slices.ContainsFunc(n.kids, p.allowed)
	}
	t := n.term
	if p.allow[t.key()] && !p.termDenied(t) {
		return true
	}
	return t.orLater && slices.ContainsFunc(choices(t), func(c term) bool { return p.allow[c.key()] && !p.deny[c.key()] })
}

// denied reports whether each choice of the expression has a denied term.
func (p *Policy) denied(n *node) bool {
	switch n.op {
	case opAnd:
		return slices.ContainsFunc(n.kids, p.denied)
	case opOr:
		for _, k := range n.kids {
			if !p.denied(k) {
				return false
			}
		}
		return true
	}
	return p.termDenied(n.term)
}

// termDenied reports a term that the deny list names, or an or-later term
// whose versions the deny list names each.
func (p *Policy) termDenied(t term) bool {
	if p.deny[t.key()] {
		return true
	}
	if !t.orLater {
		return false
	}
	for _, c := range choices(t) {
		if !p.deny[c.key()] {
			return false
		}
	}
	return true
}

func (p *Policy) deniedTerms(n *node) []string {
	if n.op == opTerm {
		if p.termDenied(n.term) {
			return []string{n.term.String()}
		}
		return nil
	}
	var out []string
	for _, k := range n.kids {
		out = append(out, p.deniedTerms(k)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// choices returns the licenses that an or-later term lets a user take, each
// with the exception of the term.
func choices(t term) []term {
	var out []term
	for _, id := range laterVersions(t.id) {
		out = append(out, term{id: id, exception: t.exception})
	}
	return out
}

// expand checks the entries and returns their keys, with each set replaced
// by its ids.
func expand(entries []string) (map[string]bool, error) {
	out := map[string]bool{}
	var bad []string
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if members, ok := setIDs(e); ok {
			for _, id := range members {
				if t, ok := canonical(id); ok && t.exception == "" {
					out[t.key()] = true
				}
			}
			continue
		}
		n, err := parseExpression(e)
		if err != nil || n.op != opTerm {
			bad = append(bad, raw)
			continue
		}
		out[n.term.key()] = true
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%q: %w", bad, errInvalidEntry)
	}
	return out, nil
}

var errInvalidEntry = errors.New("not an SPDX license id, an id WITH an exception, a LicenseRef or a set (" + strings.Join(Sets, ", ") + ")")

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
// list fails the package, whatever its unknown values are. NONE fails an
// allow list. A deny list alone cannot decide NONE, so it is unknown.
func (p *Policy) Check(d Declared) Result {
	if d.root != nil && p.Denies() && p.denied(d.root) {
		return Result{Verdict: Denied, Denied: p.deniedTerms(d.root)}
	}
	if p.Allows() && (d.None || d.root != nil && !p.allowed(d.root)) {
		return Result{Verdict: NotAllowed}
	}
	if !d.Known() || d.None {
		return Result{Verdict: Unknown}
	}
	return Result{Verdict: Pass}
}

// allowed reports whether a choice of the expression has only terms that
// the allow list names and the deny list does not.
func (p *Policy) allowed(n *node) bool {
	return satisfies(n, func(t term) bool {
		if p.allow[t.key()] && !p.termDenied(t) {
			return true
		}
		return t.orLater && slices.ContainsFunc(choices(t), func(c term) bool { return p.allow[c.key()] && !p.deny[c.key()] })
	})
}

// denied reports whether each choice of the expression has a denied term.
func (p *Policy) denied(n *node) bool {
	return !satisfies(n, func(t term) bool { return !p.termDenied(t) })
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

// satisfies reports whether a choice of the expression has only terms that
// ok accepts.
func satisfies(n *node, ok func(term) bool) bool {
	sat := func(k *node) bool { return satisfies(k, ok) }
	switch n.op {
	case opAnd:
		return !slices.ContainsFunc(n.kids, func(k *node) bool { return !sat(k) })
	case opOr:
		return slices.ContainsFunc(n.kids, sat)
	}
	return ok(n.term)
}

var freeKeys = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	ids, _ := setIDs(SetOSIApprovedOrFSF)
	addSet(out, ids)
	return out
})

// Free reports that a choice of the license has only licenses that the OSI
// approves or the FSF calls free. A WITH term counts by its license, because
// an SPDX exception adds a permission. NONE and a license that is not known
// are not free.
func Free(d Declared) bool {
	if !d.Known() || d.None {
		return false
	}
	keys := freeKeys()
	return satisfies(d.root, func(t term) bool {
		if keys[term{id: t.id}.key()] {
			return true
		}
		return t.orLater && slices.ContainsFunc(laterVersions(t.id), func(id string) bool { return keys[term{id: id}.key()] })
	})
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
			addSet(out, members)
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

func addSet(out map[string]bool, members []string) {
	for _, id := range members {
		if t, ok := canonical(id); ok && t.exception == "" {
			out[t.key()] = true
		}
	}
}

var errInvalidEntry = errors.New("not an SPDX license id, an id WITH an exception, a LicenseRef or a set (" + strings.Join(Sets, ", ") + ")")

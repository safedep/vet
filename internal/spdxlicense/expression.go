package spdxlicense

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The SPDX values of a license field that are not license expressions.
const (
	noAssertion = "NOASSERTION"
	none        = "NONE"
)

// Limits of one license value. The parser is linear, and the limits keep a
// crafted value of a package author from taking the scan's time or stack.
const (
	maxValueLen = 1024
	maxDepth    = 32
)

// Declared is the license of a package, from its declared license values.
type Declared struct {
	// Expression joins the values that parse with AND, in the canonical
	// form of each id. SPDX and CycloneDX do not define a list of declared
	// licenses, and AND is the stricter reading. It is empty when no value
	// parses.
	Expression string
	// IDs reports that each value is one active SPDX license id.
	IDs bool
	// Unknown holds the values that do not parse, and NOASSERTION.
	Unknown []string
	// None reports a NONE value: the package has no license.
	None bool

	root *node
}

// Parse reads the declared license values of a package. A package with no
// value has an unknown license.
func Parse(values []string) Declared {
	d := Declared{IDs: true}
	var parts []*node
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
		n, err := parseExpression(v)
		if err != nil {
			d.IDs = false
			d.Unknown = append(d.Unknown, v)
			continue
		}
		if _, ok := ActiveID(v); !ok {
			d.IDs = false
		}
		parts = append(parts, n)
	}
	switch len(parts) {
	case 0:
		d.IDs = false
	case 1:
		d.root = parts[0]
	default:
		d.root = &node{op: opAnd, kids: parts}
	}
	if d.root != nil {
		d.Expression = d.root.render(false)
	}
	d.Unknown = slices.Compact(d.Unknown)
	return d
}

// Known reports a license that a check can decide: an expression with no
// unknown value, or NONE.
func (d Declared) Known() bool {
	return len(d.Unknown) == 0 && (d.root != nil || d.None)
}

// ActiveID returns the active SPDX license id of v, in the case of the SPDX
// License List, or false when v is not one active id.
func ActiveID(v string) (string, bool) {
	l, ok := ids[strings.ToLower(strings.TrimSpace(v))]
	if !ok || l.Deprecated {
		return "", false
	}
	return l.ID, true
}

// Equal reports whether two lists of declared license values name the same
// license. It compares the canonical form: ids in the case of the SPDX
// License List, a deprecated id as its successor, and the operands of AND
// and OR in order. "MIT OR Apache-2.0" equals "Apache-2.0 OR MIT", and
// GPL-3.0 equals GPL-3.0-only. Values that do not parse compare as sorted
// strings.
func Equal(a, b []string) bool {
	x, y := Parse(a), Parse(b)
	if !x.Known() || !y.Known() {
		return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
	}
	return x.None == y.None && x.root.render(true) == y.root.render(true)
}

type op int

const (
	opTerm op = iota
	opAnd
	opOr
)

// node is a parsed SPDX license expression.
type node struct {
	op   op
	kids []*node
	term term
}

// term is one license: an id, an or-later id, or either WITH an exception.
type term struct {
	id        string
	orLater   bool
	exception string
}

func (t term) String() string {
	s := t.id
	if t.orLater && !strings.HasSuffix(t.id, "-or-later") {
		s += "+"
	}
	if t.exception != "" {
		s += " WITH " + t.exception
	}
	return s
}

// key is the term for a lookup in a list: ids compare with no regard to
// case, and a LicenseRef compares exactly.
func (t term) key() string {
	if isRef(t.id) {
		return t.String()
	}
	return strings.ToLower(t.String())
}

// render writes the expression. With sorted, the operands of AND and OR are
// in order and nested operators of the same kind are flat, so two spellings
// of one license render alike.
func (n *node) render(sorted bool) string {
	if n.op == opTerm {
		return n.term.String()
	}
	var parts []string
	for _, k := range n.flat(sorted) {
		s := k.render(sorted)
		if k.op != opTerm && k.op != n.op {
			s = "(" + s + ")"
		}
		parts = append(parts, s)
	}
	if sorted {
		slices.Sort(parts)
		parts = slices.Compact(parts)
	}
	sep := " AND "
	if n.op == opOr {
		sep = " OR "
	}
	return strings.Join(parts, sep)
}

func (n *node) flat(sorted bool) []*node {
	if !sorted {
		return n.kids
	}
	var out []*node
	for _, k := range n.kids {
		if k.op == n.op {
			out = append(out, k.flat(true)...)
			continue
		}
		out = append(out, k)
	}
	return out
}

var errSyntax = errors.New("not an SPDX license expression")

// parseExpression parses an SPDX license expression (SPDX 2.3 Annex D):
// WITH binds tighter than AND, and AND binds tighter than OR. It takes the
// operators in any case. Each id must be on the SPDX License List, or be a
// LicenseRef.
func parseExpression(s string) (*node, error) {
	if len(s) > maxValueLen {
		return nil, fmt.Errorf("%w: longer than %d characters", errSyntax, maxValueLen)
	}
	p := &parser{tokens: tokenize(s)}
	n, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("%w: unexpected %q", errSyntax, p.tokens[p.pos])
	}
	return n, nil
}

var parens = strings.NewReplacer("(", " ( ", ")", " ) ")

func tokenize(s string) []string {
	return strings.Fields(parens.Replace(s))
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *parser) or(depth int) (*node, error) {
	return p.binary(depth, opOr, "OR", p.and)
}

func (p *parser) and(depth int) (*node, error) {
	return p.binary(depth, opAnd, "AND", p.atom)
}

func (p *parser) binary(depth int, kind op, word string, next func(int) (*node, error)) (*node, error) {
	first, err := next(depth)
	if err != nil {
		return nil, err
	}
	kids := []*node{first}
	for strings.EqualFold(p.peek(), word) {
		p.pos++
		k, err := next(depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return &node{op: kind, kids: kids}, nil
}

func (p *parser) atom(depth int) (*node, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested deeper than %d", errSyntax, maxDepth)
	}
	tok := p.peek()
	switch {
	case tok == "":
		return nil, fmt.Errorf("%w: a license is missing", errSyntax)
	case tok == "(":
		p.pos++
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("%w: a ) is missing", errSyntax)
		}
		p.pos++
		return n, nil
	case tok == ")" || isOperator(tok):
		return nil, fmt.Errorf("%w: unexpected %q", errSyntax, tok)
	}
	p.pos++
	t, err := licenseTerm(tok)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(p.peek(), "WITH") {
		p.pos++
		e, ok := exceptions[strings.ToLower(p.peek())]
		if !ok {
			return nil, fmt.Errorf("%w: %q is not an SPDX license exception", errSyntax, p.peek())
		}
		if t.exception != "" {
			return nil, fmt.Errorf("%w: %s has two exceptions", errSyntax, tok)
		}
		p.pos++
		t.exception = e
	}
	return &node{op: opTerm, term: t}, nil
}

func isOperator(tok string) bool {
	return strings.EqualFold(tok, "AND") || strings.EqualFold(tok, "OR") || strings.EqualFold(tok, "WITH")
}

func isRef(id string) bool {
	return strings.HasPrefix(id, "LicenseRef-") || strings.HasPrefix(id, "DocumentRef-")
}

// licenseTerm reads one id with an optional +, in its canonical form.
func licenseTerm(tok string) (term, error) {
	if isRef(tok) {
		return term{id: tok}, nil
	}
	if t, ok := canonical(tok); ok {
		return t, nil
	}
	base, plus := strings.CutSuffix(tok, "+")
	if !plus || base == "" {
		return term{}, fmt.Errorf("%w: %q is not an SPDX license id", errSyntax, tok)
	}
	t, ok := canonical(base)
	if !ok || t.orLater || t.exception != "" {
		return term{}, fmt.Errorf("%w: %q is not an SPDX license id", errSyntax, tok)
	}
	if only, cut := strings.CutSuffix(t.id, "-only"); cut {
		if later, ok := ids[strings.ToLower(only+"-or-later")]; ok && !later.Deprecated {
			return term{id: later.ID, orLater: true}, nil
		}
	}
	t.orLater = true
	return t, nil
}

// canonical maps an id of the SPDX License List to its canonical term. A
// deprecated id becomes its successor when SPDX names one.
func canonical(id string) (term, bool) {
	l, ok := ids[strings.ToLower(id)]
	if !ok {
		return term{}, false
	}
	if !l.Deprecated {
		return term{id: l.ID, orLater: strings.HasSuffix(l.ID, "-or-later")}, true
	}
	if r, ok := successors[l.ID]; ok {
		return r, true
	}
	if base, plus := strings.CutSuffix(l.ID, "+"); plus {
		if later, ok := ids[strings.ToLower(base+"-or-later")]; ok && !later.Deprecated {
			return term{id: later.ID, orLater: true}, true
		}
	}
	if only, ok := ids[strings.ToLower(l.ID+"-only")]; ok && !only.Deprecated {
		return term{id: only.ID}, true
	}
	return term{id: l.ID}, true
}

// successors are the deprecated ids whose successor is not the id with
// -only or -or-later. Each follows the note of the SPDX License List.
var successors = map[string]term{
	"GPL-2.0-with-classpath-exception": {id: "GPL-2.0-only", exception: "Classpath-exception-2.0"},
	"GPL-2.0-with-GCC-exception":       {id: "GPL-2.0-only", exception: "GCC-exception-2.0"},
	"GPL-2.0-with-autoconf-exception":  {id: "GPL-2.0-only", exception: "Autoconf-exception-2.0"},
	"GPL-3.0-with-GCC-exception":       {id: "GPL-3.0-only", exception: "GCC-exception-3.1"},
	"GPL-3.0-with-autoconf-exception":  {id: "GPL-3.0-only", exception: "Autoconf-exception-3.0"},
	"BSD-2-Clause-FreeBSD":             {id: "BSD-2-Clause"},
	"BSD-2-Clause-NetBSD":              {id: "BSD-2-Clause"},
	"StandardML-NJ":                    {id: "SMLNJ"},
}

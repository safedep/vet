package policy

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"github.com/safedep/vet/v2/model"
)

// packageIdent stands in for "package", which CEL reserves. It has the same
// length, so the columns of an error stay right.
const packageIdent = "vet_pkg"

var (
	errNoKey   = errors.New("no such key")
	errNoOrder = errors.New("no version order")
)

// Expr is a compiled rule condition.
type Expr struct {
	src string
	prg cel.Program
	// reads holds the input variables that the condition reads.
	reads map[string]bool
}

func newEnv() (*cel.Env, error) {
	dyn := cel.MapType(cel.StringType, cel.DynType)
	return cel.NewEnv(
		cel.Variable("finding", dyn),
		cel.Variable(packageIdent, dyn),
		cel.Variable("manifest", dyn),
		cel.CrossTypeNumericComparisons(true),
		// package.is(name) compares a name under the rule of the ecosystem,
		// so package.is("python-dateutil") matches python.dateutil. A name
		// with *, ? or [ is a glob, as in package.is("@acme/*").
		cel.Function("is", cel.MemberOverload("package_is_string", []*cel.Type{dyn, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(pkg, name ref.Val) ref.Val {
				id, ok := celPackage(pkg)
				s, isString := name.Value().(string)
				return types.Bool(ok && isString && id.NameMatches(s))
			}))),
		// package.version_cmp(v) orders the version of the package against v
		// under the rule of the ecosystem: -1, 0 or 1. With no order, it
		// gives no answer, and a condition that needs the answer does not
		// match. CEL still decides a || b from a true b, as it does for an
		// absent field, so a deny rule keeps its other checks.
		cel.Function("version_cmp", cel.MemberOverload("package_version_cmp_string", []*cel.Type{dyn, cel.StringType}, cel.IntType,
			cel.BinaryBinding(func(pkg, version ref.Val) ref.Val {
				id, ok := celPackage(pkg)
				v, isString := version.Value().(string)
				if !ok || !isString {
					return types.NewErr("%s", errNoKey)
				}
				c, err := id.Compare(id.WithVersion(v))
				if err != nil {
					return types.WrapErr(fmt.Errorf("%w: %w", errNoOrder, err))
				}
				return types.Int(c)
			}))),
	)
}

// celPackage rebuilds the package version of the CEL package input from its
// ecosystem and its raw form. It is false for a finding with no package.
func celPackage(v ref.Val) (model.PackageVersion, bool) {
	m, ok := v.(traits.Mapper)
	if !ok {
		return model.PackageVersion{}, false
	}
	field := func(key string) string {
		f, found := m.Find(types.String(key))
		if !found {
			return ""
		}
		s, _ := f.Value().(string)
		return s
	}
	id, err := model.NewPackageVersion(model.Ecosystem(field("ecosystem")), field("raw_name"), field("raw_version"))
	return id, err == nil
}

// Compile compiles a rule condition. The condition must give a bool.
func Compile(src string) (*Expr, error) {
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("create the CEL environment: %w", err)
	}
	ast, iss := env.Compile(rewritePackage(src))
	if iss.Err() != nil {
		return nil, errors.New(restorePackage(iss.Err().Error()))
	}
	if t := ast.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
		return nil, fmt.Errorf("the condition gives %s, not bool", t)
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, errors.New(restorePackage(err.Error()))
	}
	return &Expr{src: src, prg: prg, reads: idents(ast)}, nil
}

// idents returns the input variables that a condition reads. A variable
// of a macro, as v in exists(v, ...), hides an input variable of the same
// name inside the macro.
func idents(a *cel.Ast) map[string]bool {
	out := map[string]bool{}
	var walk func(e celast.Expr, local map[string]bool)
	walk = func(e celast.Expr, local map[string]bool) {
		switch e.Kind() {
		case celast.IdentKind:
			if !local[e.AsIdent()] {
				out[e.AsIdent()] = true
			}
		case celast.SelectKind:
			walk(e.AsSelect().Operand(), local)
		case celast.CallKind:
			c := e.AsCall()
			if c.IsMemberFunction() {
				walk(c.Target(), local)
			}
			for _, arg := range c.Args() {
				walk(arg, local)
			}
		case celast.ListKind:
			for _, el := range e.AsList().Elements() {
				walk(el, local)
			}
		case celast.MapKind:
			for _, en := range e.AsMap().Entries() {
				walk(en.AsMapEntry().Key(), local)
				walk(en.AsMapEntry().Value(), local)
			}
		case celast.StructKind:
			for _, f := range e.AsStruct().Fields() {
				walk(f.AsStructField().Value(), local)
			}
		case celast.ComprehensionKind:
			c := e.AsComprehension()
			walk(c.IterRange(), local)
			walk(c.AccuInit(), local)
			inner := maps.Clone(local)
			inner[c.IterVar()], inner[c.AccuVar()] = true, true
			if c.HasIterVar2() {
				inner[c.IterVar2()] = true
			}
			walk(c.LoopCondition(), inner)
			walk(c.LoopStep(), inner)
			walk(c.Result(), inner)
		}
	}
	walk(a.NativeRep().Expr(), map[string]bool{})
	return out
}

// Match evaluates the condition on an input. A condition that reads an
// absent optional field, such as package.days_since_publish of a package
// with no publish date, does not match, and gives no error.
func (e *Expr) Match(in Input) (bool, error) {
	vars, err := in.activation()
	if err != nil {
		return false, err
	}
	return e.matchVars(vars)
}

// matchVars evaluates the condition on the CEL variables of an input, so a
// caller that runs many rules on one input builds the variables once.
func (e *Expr) matchVars(vars map[string]any) (bool, error) {
	out, _, err := e.prg.Eval(vars)
	if err != nil {
		// CEL gives a missing map key as text, with no error to match.
		if errors.Is(err, errNoOrder) || strings.Contains(err.Error(), errNoKey.Error()) {
			return false, nil
		}
		return false, errors.New(restorePackage(err.Error()))
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("the condition gave %v, not a bool", out.Value())
	}
	return b, nil
}

// rewritePackage replaces the identifier "package" outside string literals.
// A field that is named package, as in x.package, stays.
func rewritePackage(src string) string {
	const word = "package"
	var b strings.Builder
	for i := 0; i < len(src); {
		if q := quoteAt(src, i); q != "" {
			end := closeQuote(src, i+len(q), q)
			b.WriteString(src[i:end])
			i = end
			continue
		}
		if strings.HasPrefix(src[i:], word) && !identByte(at(src, i-1)) && at(src, i-1) != '.' &&
			!identByte(at(src, i+len(word))) {
			b.WriteString(packageIdent)
			i += len(word)
			continue
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String()
}

func restorePackage(msg string) string { return strings.ReplaceAll(msg, packageIdent, "package") }

// quoteAt returns the quote that opens a string literal at i, with any raw
// or bytes prefix, or "".
func quoteAt(src string, i int) string {
	j := i
	for j < len(src) && j-i < 2 && strings.ContainsRune("rRbB", rune(src[j])) {
		j++
	}
	if j > i && identByte(at(src, i-1)) {
		return ""
	}
	for _, q := range []string{`"""`, `'''`, `"`, `'`} {
		if strings.HasPrefix(src[j:], q) {
			return src[i:j] + q
		}
	}
	return ""
}

// closeQuote returns the index after the quote that closes a literal.
func closeQuote(src string, i int, open string) int {
	q := strings.TrimLeft(open, "rRbB")
	raw := strings.ContainsAny(open[:len(open)-len(q)], "rR")
	for i < len(src) {
		if !raw && src[i] == '\\' {
			i += 2
			continue
		}
		if strings.HasPrefix(src[i:], q) {
			return i + len(q)
		}
		i++
	}
	return len(src)
}

func at(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

func identByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

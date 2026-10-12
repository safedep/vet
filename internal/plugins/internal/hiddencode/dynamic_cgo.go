//go:build cgo

package hiddencode

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/safedep/code/core"
	"github.com/safedep/code/lang"
	"github.com/safedep/code/lang/ecmascript"
	"github.com/safedep/code/parser"
	"github.com/safedep/code/pkg/ts"
	sitter "github.com/smacker/go-tree-sitter"
)

// dynamicCodeAvailable reports that this build parses JavaScript. The
// dynamic-code check and the script check of text assets use safedep/code,
// which needs CGO for tree-sitter.
const dynamicCodeAvailable = true

// dynamicKind is one way for code to run code that a reader cannot see.
type dynamicKind int

const (
	dynEval dynamicKind = iota + 1
	dynFunction
	dynVM
	dynRequire
	dynGlobal
	dynAlias
	dynProcess
	dynUnread
)

// dynamicText words the title and the snippet of each kind. The snippet
// names the kind, never the payload.
var dynamicText = map[dynamicKind]struct{ title, snippet string }{
	dynEval:     {"calls eval", "eval(...)"},
	dynFunction: {"calls the Function constructor", "Function(...)"},
	dynVM:       {"runs code with the vm module", "vm.runIn...(...)"},
	dynRequire:  {"loads a module by a name that it builds at run time", "require(<computed>)"},
	dynGlobal:   {"puts require, eval or Function, or a key that it computes, on the global object", "global[...] = ..."},
	dynAlias:    {"keeps require, eval or Function under another name", "x = require"},
	dynProcess:  {"starts a process with a command that it builds at run time", "child_process(<computed>)"},
	dynUnread:   {"is too large or too complex for vet to read in full", "<not read>"},
}

var (
	vmRun = map[string]bool{"runInThisContext": true, "runInNewContext": true, "runInContext": true, "compileFunction": true}
	// processes are the child_process calls that run a command. exec is
	// one only on a child_process binding, because regular expressions
	// have an exec method too.
	processes   = map[string]bool{"exec": true, "execSync": true, "spawn": true, "spawnSync": true, "execFile": true, "execFileSync": true, "fork": true}
	namedRunner = map[string]bool{"execSync": true, "spawn": true, "spawnSync": true, "execFile": true, "execFileSync": true, "fork": true}
	// fileRoots are the expressions that give the folder of the config, so
	// a path built on them names a file.
	fileRoots = map[string]bool{"__dirname": true, "__filename": true, "import.meta.dirname": true, "import.meta.filename": true, "process.cwd()": true}
	// processModules are the names of the child_process module.
	processModules = []string{"child_process", "node:child_process"}
	loaders        = map[string]bool{"require": true, "eval": true, "Function": true}
)

const (
	// parseTimeout bounds the parse and the analysis of one file. Some
	// inputs make the tree-sitter parse slow.
	parseTimeout = 30 * time.Second

	// maxScriptSize is the largest text asset that runsAsScript parses. It
	// is above MaxSize, because a comment can pad a script past the config
	// limit. The parse of a larger asset costs seconds and gigabytes, so the
	// text check reads it in place of the parse. The node limit of Diagnose
	// stops a dense asset below this size.
	maxScriptSize = 8 << 20
)

// dynamicCode finds code in a build config or an npm entry script that runs
// code that a reader cannot see. A config only declares settings, so it
// has no reason to call eval, build a function from a string, load a module
// by a name that it computes, or keep require under another name. The
// check reads what each name stands for, not the name, because a loader
// renames require (global['r']=require) and hides its strings in tables.
// A file that vet cannot read in full gives a finding too, because a loader
// can hide behind the limits of the parse.
func dynamicCode(c Class, p string, data []byte) []Signal {
	what := "The build config"
	if c == Entry {
		what = "The npm entry script"
	}
	signal := func(k dynamicKind, line int) Signal {
		t := dynamicText[k]
		return Signal{ID: IDDynamicCode, Line: line, Visible: t.snippet, Title: fmt.Sprintf("%s %s on line %d", what, t.title, line)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()
	tree, err := parseJS(ctx, languageOf(p), data, MaxSize+1)
	if err != nil {
		return []Signal{signal(dynUnread, 1)}
	}
	defer tree.Tree().Close()
	a, err := ecmascript.Analyze(ctx, tree, ecmascript.Options{})
	if err != nil {
		return []Signal{signal(dynUnread, 1)}
	}

	type hit struct {
		kind dynamicKind
		node *sitter.Node
	}
	var hits []hit
	for _, call := range a.Calls() {
		if k := callKind(a, call); k != 0 {
			hits = append(hits, hit{k, call.Node})
		}
	}
	for _, as := range a.Assignments() {
		if onGlobal(a, as.Object) && (as.Computed || isLoader(a, as.Right)) {
			hits = append(hits, hit{dynGlobal, as.Node})
		}
	}
	for _, b := range a.Bindings() {
		if b.Node.Type() != "variable_declarator" || b.Value == nil {
			continue
		}
		v := a.Unparen(b.Value)
		if v == nil || (b.Member == "" && v.Type() != "identifier") {
			continue
		}
		if aliasesLoader(a, b.Name) || (b.Member == "" && b.Name != a.Name(v) && isLoader(a, v)) {
			hits = append(hits, hit{dynAlias, b.Node})
		}
	}
	slices.SortStableFunc(hits, func(x, y hit) int { return cmp.Compare(x.node.StartByte(), y.node.StartByte()) })

	var out []Signal
	// Eval can drop values at the value limit, so Truncated is read after
	// the checks.
	if a.Truncated() {
		out = append(out, signal(dynUnread, 1))
	}
	found := map[dynamicKind]bool{}
	for _, h := range hits {
		if !found[h.kind] {
			found[h.kind] = true
			out = append(out, signal(h.kind, int(h.node.StartPoint().Row)+1))
		}
	}
	return out
}

// languageOf returns TypeScript with no JSX for a .ts, .mts or .cts file,
// and JavaScript for any other file. node runs a required file of any name
// as JavaScript.
func languageOf(p string) core.Language {
	switch strings.ToLower(path.Ext(p)) {
	case ".ts", ".mts", ".cts":
		if l, err := lang.NewTypescriptWithoutJSXLanguage(); err == nil {
			return l
		}
	}
	l, err := lang.NewJavascriptLanguage()
	if err != nil {
		return nil
	}
	return l
}

func parseJS(ctx context.Context, l core.Language, data []byte, maxBytes int) (core.ParseTree, error) {
	if l == nil {
		return nil, fmt.Errorf("no JavaScript grammar")
	}
	return parser.ParseBytes(ctx, l, data, parser.WithMaxBytes(maxBytes))
}

func callKind(a *ecmascript.Analysis, c ecmascript.Call) dynamicKind {
	targets := a.Eval(c.Callee)
	calls := func(name string) bool {
		return c.Name == name || slices.ContainsFunc(targets, func(v ecmascript.Value) bool { return v.IsGlobal(name) })
	}
	arg := payload(a, c)
	switch {
	case c.New:
		if calls("Function") {
			return dynFunction
		}
	case calls("eval"):
		return dynEval
	case calls("Function") || constructorChain(a, c.Callee):
		return dynFunction
	case vmRun[c.Name] && c.Callee.Type() == "member_expression":
		return dynVM
	case calls("require") || c.Callee.Type() == "import":
		if computed(a, arg) && !isFilePath(a, arg) {
			return dynRequire
		}
	case runsProcess(c, targets) && computed(a, arg):
		return dynProcess
	}
	return 0
}

// payload returns the argument that a call passes on: the first one, or
// the second one of f.call(t, x) and f.apply(t, x), where the first one is
// the this value.
func payload(a *ecmascript.Analysis, c ecmascript.Call) *sitter.Node {
	if c.Callee.Type() == "member_expression" {
		switch a.Name(c.Callee.ChildByFieldName("property")) {
		case "call", "apply":
			return c.Arg(1)
		}
	}
	return c.Arg(0)
}

// runsProcess reports a call of a child_process runner, or of a runner
// name that only child_process uses.
func runsProcess(c ecmascript.Call, targets []ecmascript.Value) bool {
	if namedRunner[c.Name] {
		return true
	}
	return slices.ContainsFunc(targets, func(v ecmascript.Value) bool {
		return processes[v.Member] && v.IsModuleMember(v.Member, processModules...)
	})
}

// onGlobal reports an object that stands for global or globalThis. A
// browser config writes to window and self, so they do not count.
func onGlobal(a *ecmascript.Analysis, n *sitter.Node) bool {
	return slices.ContainsFunc(a.Eval(n), func(v ecmascript.Value) bool { return v.IsGlobal("global", "globalThis") })
}

func isLoaderValue(v ecmascript.Value) bool { return v.IsGlobal("require", "eval", "Function") }

// isLoader reports an expression that stands for require, eval or
// Function, or that is one of these names. A file that declares
// var require at its top level still gets require from node.
func isLoader(a *ecmascript.Analysis, n *sitter.Node) bool {
	return loaders[a.Name(a.Unparen(n))] || slices.ContainsFunc(a.Eval(n), isLoaderValue)
}

// aliasesLoader reports a name that the file binds to require, eval or
// Function. A name also stands for its own global, so a local named
// require in a function, as const require = x, is not an alias.
func aliasesLoader(a *ecmascript.Analysis, name string) bool {
	return slices.ContainsFunc(a.Resolve(name), func(v ecmascript.Value) bool {
		return !v.IsGlobal(name) && isLoaderValue(v)
	})
}

// computed reports an argument that is not a plain string: a call, a sum
// or a template with a substitution. A name is not computed, because code
// passes a path that it built before, as npm does with require(cliEntry).
func computed(a *ecmascript.Analysis, arg *sitter.Node) bool {
	switch a.ClassifyArg(arg) {
	case ecmascript.ArgNone, ecmascript.ArgString, ecmascript.ArgName, ecmascript.ArgMember:
		return false
	}
	return true
}

// runsAsScript reports a text asset that node can run: it parses as
// JavaScript with no error, calls a function and holds a script token.
// node runs a required file of any name as JavaScript, but a style sheet,
// an SVG image or a source map does not parse as JavaScript with a call.
// tree-sitter reads an SVG image as JSX, which node does not run. node
// accepts a NUL byte in a comment, and tree-sitter stops at one, so a NUL
// byte becomes a space. An asset that the parse cannot read in full gives
// parsed false, so the text check reads it.
func runsAsScript(data []byte) (runs, parsed bool) {
	if scriptTokens(data, nil) == 0 {
		return false, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()
	tree, err := parseJS(ctx, languageOf(""), bytes.ReplaceAll(data, []byte{0}, []byte{' '}), maxScriptSize)
	if err != nil {
		return false, false
	}
	defer tree.Tree().Close()
	root := tree.Tree().RootNode()
	if root.HasError() {
		return false, true
	}
	d, err := ts.Diagnose(ctx, root, 0)
	if err != nil {
		return false, false
	}
	for k := range d.Kinds {
		if strings.HasPrefix(k, "jsx_") {
			return false, true
		}
	}
	return d.Kinds["call_expression"] || d.Kinds["new_expression"], true
}

// constructorChain reports x.constructor.constructor, which is Function.
func constructorChain(a *ecmascript.Analysis, fn *sitter.Node) bool {
	if fn.Type() != "member_expression" || a.Name(fn.ChildByFieldName("property")) != "constructor" {
		return false
	}
	obj := a.Unparen(fn.ChildByFieldName("object"))
	return obj != nil && obj.Type() == "member_expression" && a.Name(obj.ChildByFieldName("property")) == "constructor"
}

// isFilePath reports a module path that names a file: a relative path, a
// path that path.resolve builds, which is always absolute, or a path that
// path.join builds on the folder of the config. A file path never names a
// built-in module such as child_process.
func isFilePath(a *ecmascript.Analysis, n *sitter.Node) bool {
	n = a.Unparen(n)
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "template_string":
		s, _ := a.StringPrefix(n)
		return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
	case "binary_expression":
		return isFilePath(a, n.ChildByFieldName("left"))
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Type() != "member_expression" || a.Name(fn.ChildByFieldName("object")) != "path" {
			return false
		}
		switch a.Name(fn.ChildByFieldName("property")) {
		case "resolve":
			return true
		case "join":
			args := ecmascript.Args(n)
			if len(args) == 0 {
				return false
			}
			first := a.Unparen(args[0])
			return fileRoots[a.Name(first)] || isFilePath(a, first)
		}
	}
	return false
}

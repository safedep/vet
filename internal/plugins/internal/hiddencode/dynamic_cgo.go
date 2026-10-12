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
)

// processModules are the names of the child_process module.
var processModules = []string{"child_process", "node:child_process"}

// parseTimeout bounds the parse and the analysis of one file. Some inputs
// make the tree-sitter parse slow.
const parseTimeout = 30 * time.Second

// dynamicCode finds code in a build config or an npm entry script that runs
// code that a reader cannot see. A config only declares settings, so it
// has no reason to call eval, build a function from a string, load a module
// by a name that it computes, or keep require under another name. The
// check reads what each name stands for, not the name, because a loader
// renames require (global['r']=require) and hides its strings in tables.
func dynamicCode(c Class, p string, data []byte) []Signal {
	var l core.Language
	var err error
	switch strings.ToLower(path.Ext(p)) {
	case ".ts", ".mts", ".cts":
		l, err = lang.NewTypescriptWithoutJSXLanguage()
	default:
		l, err = lang.NewJavascriptLanguage()
	}
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()
	tree, err := parser.ParseBytes(ctx, l, data, parser.WithMaxBytes(maxAssetSize+1))
	if err != nil {
		return nil
	}
	a, err := ecmascript.Analyze(ctx, tree, ecmascript.Options{MaxNodes: -1})
	if err != nil {
		return nil
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
		if as.Global && (as.Computed || isLoader(a, as.Right)) {
			hits = append(hits, hit{dynGlobal, as.Node})
		}
	}
	for _, b := range a.Bindings() {
		if b.Node.Type() != "variable_declarator" || b.Value == nil {
			continue
		}
		if v := a.Unparen(b.Value); v != nil && (b.Member != "" || v.Type() == "identifier") && aliasesLoader(a, b.Name) {
			hits = append(hits, hit{dynAlias, b.Node})
		}
	}
	slices.SortStableFunc(hits, func(x, y hit) int { return cmp.Compare(x.node.StartByte(), y.node.StartByte()) })

	what := "The build config"
	if c == Entry {
		what = "The npm entry script"
	}
	found := map[dynamicKind]bool{}
	var out []Signal
	for _, h := range hits {
		if found[h.kind] {
			continue
		}
		found[h.kind] = true
		line := int(h.node.StartPoint().Row) + 1
		t := dynamicText[h.kind]
		out = append(out, Signal{ID: IDDynamicCode, Line: line, Visible: t.snippet, Title: fmt.Sprintf("%s %s on line %d", what, t.title, line)})
	}
	return out
}

func callKind(a *ecmascript.Analysis, c ecmascript.Call) dynamicKind {
	targets := a.Eval(c.Callee)
	is := func(names ...string) bool {
		return slices.ContainsFunc(targets, func(v ecmascript.Value) bool { return v.IsGlobal(names...) })
	}
	switch {
	case c.New:
		if is("Function") || c.Name == "Function" {
			return dynFunction
		}
	case is("eval") || c.Name == "eval":
		return dynEval
	case is("Function") || c.Name == "Function" || constructorChain(a, c.Callee):
		return dynFunction
	case vmRun[c.Name] && c.Callee.Type() == "member_expression":
		return dynVM
	case is("require") || c.Name == "require" || c.Callee.Type() == "import":
		if computed(a, c.Arg(0)) && !isFilePath(a, c.Arg(0)) {
			return dynRequire
		}
	case runsProcess(c, targets) && computed(a, c.Arg(0)):
		return dynProcess
	}
	return 0
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

func isLoaderValue(v ecmascript.Value) bool { return v.IsGlobal("require", "eval", "Function") }

// isLoader reports an expression that stands for require, eval or
// Function.
func isLoader(a *ecmascript.Analysis, n *sitter.Node) bool {
	return slices.ContainsFunc(a.Eval(n), isLoaderValue)
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
// byte becomes a space.
func runsAsScript(data []byte) (runs, parsed bool) {
	if scriptTokens(data, nil) == 0 {
		return false, true
	}
	l, err := lang.NewJavascriptLanguage()
	if err != nil {
		return false, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()
	tree, err := parser.ParseBytes(ctx, l, bytes.ReplaceAll(data, []byte{0}, []byte{' '}), parser.WithMaxBytes(maxAssetSize+1))
	if err != nil {
		return false, true
	}
	d, err := ts.Diagnose(ctx, tree.Tree().RootNode(), -1)
	if err != nil || d.HasError {
		return false, true
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

//go:build cgo

package hiddencode

import (
	"context"
	"fmt"
	"path"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// dynamicCodeAvailable reports that this build reads configs for dynamic
// code. The check parses JavaScript with tree-sitter, which needs CGO.
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
	globals     = map[string]bool{"global": true, "globalThis": true}
	loaders     = map[string]bool{"require": true, "eval": true, "Function": true}
	// fileRoots are the expressions that give the folder of the config, so
	// a path built on them names a file.
	fileRoots = map[string]bool{"__dirname": true, "__filename": true, "import.meta.dirname": true, "import.meta.filename": true, "process.cwd()": true}
)

// dynamicCode finds code in a build config or an npm entry script that runs
// code that a reader cannot see. A config only declares settings, so it
// has no reason to call eval, build a function from a string, load a module
// by a name that it computes, or keep require under another name. The
// check reads the syntax tree, not names, because a loader renames require
// (global['r']=require) and hides its strings in tables.
func dynamicCode(c Class, p string, data []byte) []Signal {
	lang := javascript.GetLanguage()
	switch strings.ToLower(path.Ext(p)) {
	case ".ts", ".mts", ".cts":
		lang = typescript.GetLanguage()
	}
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(lang)
	tree, err := parser.ParseCtx(context.Background(), nil, data)
	if err != nil {
		return nil
	}
	defer tree.Close()

	what := "The build config"
	if c == Entry {
		what = "The npm entry script"
	}
	w := dynamicWalk{src: data, modules: map[string]bool{}, runners: map[string]bool{}}
	w.walk(tree.RootNode(), w.bind)
	found := map[dynamicKind]bool{}
	var out []Signal
	w.walk(tree.RootNode(), func(n *sitter.Node) {
		if k := w.kindOf(n); k != 0 && !found[k] {
			found[k] = true
			line := int(n.StartPoint().Row) + 1
			t := dynamicText[k]
			out = append(out, Signal{ID: IDDynamicCode, Line: line, Visible: t.snippet, Title: fmt.Sprintf("%s %s on line %d", what, t.title, line)})
		}
	})
	return out
}

// dynamicWalk holds the names that a file binds to child_process: the
// module, as cp in const cp = require('child_process'), and its runners, as
// exec in const { exec } = require('child_process').
type dynamicWalk struct {
	src     []byte
	modules map[string]bool
	runners map[string]bool
}

func (w *dynamicWalk) walk(root *sitter.Node, visit func(*sitter.Node)) {
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visit(n)
		for i := int(n.NamedChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.NamedChild(i))
		}
	}
}

func (w *dynamicWalk) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(w.src)
}

// bind records the names that a declaration or an import binds to
// child_process.
func (w *dynamicWalk) bind(n *sitter.Node) {
	switch n.Type() {
	case "variable_declarator":
		if w.isProcessModule(n.ChildByFieldName("value")) {
			w.bindPattern(n.ChildByFieldName("name"))
		}
	case "import_statement":
		if !isProcessName(stringValue(n.ChildByFieldName("source"), w.src)) {
			return
		}
		w.walk(n, func(c *sitter.Node) {
			switch c.Type() {
			case "import_specifier":
				name := c.ChildByFieldName("alias")
				if name == nil {
					name = c.ChildByFieldName("name")
				}
				w.runners[w.text(name)] = true
			case "namespace_import":
				w.modules[w.text(c.NamedChild(0))] = true
			case "import_clause":
				if first := c.NamedChild(0); first != nil && first.Type() == "identifier" {
					w.modules[w.text(first)] = true
				}
			}
		})
	}
}

func (w *dynamicWalk) bindPattern(name *sitter.Node) {
	if name == nil {
		return
	}
	if name.Type() == "identifier" {
		w.modules[w.text(name)] = true
		return
	}
	w.walk(name, func(c *sitter.Node) {
		switch c.Type() {
		case "shorthand_property_identifier_pattern":
			w.runners[w.text(c)] = true
		case "pair_pattern":
			w.runners[w.text(c.ChildByFieldName("value"))] = true
		}
	})
}

// isProcessModule reports require('child_process') or its node: form.
func (w *dynamicWalk) isProcessModule(n *sitter.Node) bool {
	if n == nil || n.Type() != "call_expression" || w.text(n.ChildByFieldName("function")) != "require" {
		return false
	}
	return isProcessName(stringValue(firstArg(n.ChildByFieldName("arguments")), w.src))
}

func isProcessName(s string) bool { return s == "child_process" || s == "node:child_process" }

func (w *dynamicWalk) kindOf(n *sitter.Node) dynamicKind {
	switch n.Type() {
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return 0
		}
		args := n.ChildByFieldName("arguments")
		switch name := callee(fn, w.src); {
		case name == "eval":
			return dynEval
		case name == "Function", strings.HasSuffix(w.text(fn), "constructor.constructor"):
			return dynFunction
		case vmRun[name] && fn.Type() == "member_expression":
			return dynVM
		case name == "require" || fn.Type() == "import":
			if computed(args) && !w.isFilePath(firstArg(args)) {
				return dynRequire
			}
		case w.runsProcess(fn, name) && computed(args):
			return dynProcess
		}
	case "new_expression":
		if callee(n.ChildByFieldName("constructor"), w.src) == "Function" {
			return dynFunction
		}
	case "assignment_expression":
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if left == nil || right == nil || !globals[w.text(left.ChildByFieldName("object"))] {
			return 0
		}
		if loaders[w.text(right)] || (left.Type() == "subscript_expression" && !isString(left.ChildByFieldName("index"))) {
			return dynGlobal
		}
	case "variable_declarator":
		if v := n.ChildByFieldName("value"); v != nil && v.Type() == "identifier" && loaders[w.text(v)] {
			return dynAlias
		}
	}
	return 0
}

// runsProcess reports a call of a child_process runner: a bound runner, a
// runner of a bound module or of require('child_process'), or a runner
// name that only child_process uses.
func (w *dynamicWalk) runsProcess(fn *sitter.Node, name string) bool {
	switch fn.Type() {
	case "identifier":
		return w.runners[name] || namedRunner[name]
	case "member_expression":
		obj := fn.ChildByFieldName("object")
		return processes[name] && (w.modules[w.text(obj)] || w.isProcessModule(obj)) || namedRunner[name]
	}
	return false
}

// isFilePath reports a module path that names a file: a relative path, a
// path that path.resolve builds, which is always absolute, or a path that
// path.join builds on the folder of the config. A file path never names a
// built-in module such as child_process.
func (w *dynamicWalk) isFilePath(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "template_string":
		s := strings.Trim(w.text(n), "'\"`")
		return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
	case "binary_expression":
		return w.isFilePath(n.ChildByFieldName("left"))
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Type() != "member_expression" || w.text(fn.ChildByFieldName("object")) != "path" {
			return false
		}
		switch w.text(fn.ChildByFieldName("property")) {
		case "resolve":
			return true
		case "join":
			first := firstArg(n.ChildByFieldName("arguments"))
			return fileRoots[w.text(first)] || w.isFilePath(first)
		}
	}
	return false
}

// callee returns the name that a call calls: eval for eval(x), (0, eval)(x)
// and globalThis.eval(x), and the property for a member call.
func callee(fn *sitter.Node, src []byte) string {
	for fn != nil {
		switch fn.Type() {
		case "identifier", "property_identifier":
			return fn.Content(src)
		case "member_expression":
			fn = fn.ChildByFieldName("property")
		case "parenthesized_expression", "sequence_expression":
			// (0, eval) calls the last expression of the list.
			fn = fn.NamedChild(int(fn.NamedChildCount()) - 1)
		default:
			return ""
		}
	}
	return ""
}

func firstArg(args *sitter.Node) *sitter.Node {
	if args == nil || args.NamedChildCount() == 0 {
		return nil
	}
	return args.NamedChild(0)
}

func isString(n *sitter.Node) bool {
	return n != nil && (n.Type() == "string" || (n.Type() == "template_string" && !hasSubstitution(n)))
}

func hasSubstitution(n *sitter.Node) bool {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if n.NamedChild(i).Type() == "template_substitution" {
			return true
		}
	}
	return false
}

// stringValue returns the text of a plain string, or "".
func stringValue(n *sitter.Node, src []byte) string {
	if !isString(n) {
		return ""
	}
	return strings.Trim(n.Content(src), "'\"`")
}

// computed reports a first argument that is not a plain string: a call, a
// sum or a template with a substitution. A name is not computed, because
// code passes a path that it built before, as npm does with
// require(cliEntry).
func computed(args *sitter.Node) bool {
	a := firstArg(args)
	if a == nil {
		return false
	}
	switch a.Type() {
	case "identifier", "member_expression":
		return false
	}
	return !isString(a)
}

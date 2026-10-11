//go:build cgo

package hiddencode

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// DynamicCodeAvailable reports that this build reads configs for dynamic
// code. The check parses JavaScript with tree-sitter, which needs CGO.
const DynamicCodeAvailable = true

// maxDynamic is the largest file that the dynamic code check parses. A
// larger config is a finding of its own.
const maxDynamic = 1 << 20

// dynamicKind is one way for code to run code that a reader cannot see.
type dynamicKind int

const (
	dynEval dynamicKind = iota + 1
	dynFunction
	dynVM
	dynRequire
	dynGlobal
	dynProcess
)

// dynamicText words the title and the snippet of each kind. The snippet
// names the kind, never the payload.
var dynamicText = map[dynamicKind]struct{ title, snippet string }{
	dynEval:     {"calls eval", "eval(...)"},
	dynFunction: {"calls the Function constructor", "Function(...)"},
	dynVM:       {"runs code with the vm module", "vm.runIn...(...)"},
	dynRequire:  {"loads a module by a name that it builds at run time", "require(<computed>)"},
	dynGlobal:   {"puts a loader or a computed key on the global object", "global[...] = ..."},
	dynProcess:  {"starts a process with a command that it builds at run time", "child_process(<computed>)"},
}

var (
	vmRun     = map[string]bool{"runInThisContext": true, "runInNewContext": true, "runInContext": true, "compileFunction": true}
	processes = map[string]bool{"execSync": true, "spawn": true, "spawnSync": true, "execFile": true, "execFileSync": true, "fork": true}
	globals   = map[string]bool{"global": true, "globalThis": true}
	loaders   = map[string]bool{"require": true, "eval": true, "Function": true, "module": true}
	// localPath is a module path that starts at the project: a relative
	// path, or a path built on the folder of the config.
	localPath = regexp.MustCompile(`^\s*['"` + "`" + `]\.{1,2}/|__dirname|__filename|import\.meta|process\.cwd\(\)`)
)

// dynamicCode finds code in a build config or an npm entry script that runs
// code that a reader cannot see. A config only declares settings, so it
// has no reason to call eval, build a function from a string, load a module
// by a name that it computes, or put require on the global object. The
// check reads the syntax tree, not names, because a loader renames require
// (global['r']=require) and hides its strings in tables.
func dynamicCode(c Class, p string, data []byte) []Signal {
	if len(data) > maxDynamic {
		return nil
	}
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
	found := map[dynamicKind]bool{}
	var out []Signal
	stack := []*sitter.Node{tree.RootNode()}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if k := dynamicOf(n, data); k != 0 && !found[k] {
			found[k] = true
			line := int(n.StartPoint().Row) + 1
			t := dynamicText[k]
			out = append(out, Signal{ID: IDDynamicCode, Line: line, Visible: t.snippet, Title: fmt.Sprintf("%s %s on line %d", what, t.title, line)})
		}
		for i := int(n.NamedChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.NamedChild(i))
		}
	}
	return out
}

func dynamicOf(n *sitter.Node, src []byte) dynamicKind {
	switch n.Type() {
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return 0
		}
		args := n.ChildByFieldName("arguments")
		switch name := callee(fn, src); {
		case name == "eval":
			return dynEval
		case name == "Function", strings.HasSuffix(fn.Content(src), "constructor.constructor"):
			return dynFunction
		case vmRun[name] && fn.Type() == "member_expression":
			return dynVM
		case name == "require" || fn.Type() == "import":
			if computed(args, src) && !localPath.MatchString(firstArg(args).Content(src)) {
				return dynRequire
			}
		case processes[name] && computed(args, src):
			return dynProcess
		}
	case "new_expression":
		if callee(n.ChildByFieldName("constructor"), src) == "Function" {
			return dynFunction
		}
	case "assignment_expression":
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if left == nil || right == nil {
			return 0
		}
		obj := left.ChildByFieldName("object")
		if obj == nil || !globals[obj.Content(src)] {
			return 0
		}
		if left.Type() == "subscript_expression" || loaders[right.Content(src)] {
			return dynGlobal
		}
	}
	return 0
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

// computed reports a first argument that is not a plain string: a name, a
// call, a sum or a template with a substitution. A plain identifier is not
// computed, because code passes a path that it built before, as npm does
// with require(cliEntry).
func computed(args *sitter.Node, src []byte) bool {
	a := firstArg(args)
	if a == nil {
		return false
	}
	switch a.Type() {
	case "string", "identifier", "member_expression":
		return false
	case "template_string":
		for i := 0; i < int(a.NamedChildCount()); i++ {
			if a.NamedChild(i).Type() == "template_substitution" {
				return true
			}
		}
		return false
	}
	return true
}

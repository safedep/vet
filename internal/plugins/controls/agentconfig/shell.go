package agentconfig

import (
	"maps"
	"path"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

const (
	// maxShellText is the longest command that vet parses. A longer command
	// still goes through the patterns as text.
	maxShellText = 64 << 10
	// maxShellDepth bounds the sh -c scripts inside a command.
	maxShellDepth = 3
)

// shellNames are the shells that run the text on their input or in -c.
var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true,
	"cmd": true, "powershell": true, "pwsh": true,
}

// sources run a script file in the current shell, as in source <(curl x).
var sources = map[string]bool{"source": true, ".": true}

// downloaders fetch a file from the network.
var downloaders = map[string]bool{
	"curl": true, "wget": true, "iwr": true, "irm": true,
	"invoke-webrequest": true, "invoke-restmethod": true,
}

// wrappers run the command that follows their own options, as in
// env X=1 sh or sudo -u root sh.
var wrappers = map[string]bool{
	"env": true, "sudo": true, "doas": true, "exec": true, "command": true,
	"nohup": true, "nice": true, "time": true, "busybox": true,
	"timeout": true, "setsid": true, "stdbuf": true, "xargs": true,
}

// wrapperValueFlags are the options of each wrapper that take the next
// word, as in sudo -u root sh. The same letter takes no word in another
// wrapper: sudo -n sh is not sudo with the user sh.
var wrapperValueFlags = map[string]map[string]bool{
	"env": {"-u": true, "-C": true, "--unset": true, "--chdir": true},
	"sudo": {
		"-u": true, "-g": true, "-C": true, "-p": true, "-U": true, "-h": true, "-D": true, "-R": true, "-T": true,
		"--user": true, "--group": true, "--close-from": true, "--prompt": true, "--other-user": true,
		"--host": true, "--chdir": true, "--chroot": true, "--command-timeout": true,
	},
	"doas":    {"-u": true, "-C": true},
	"exec":    {"-a": true},
	"nice":    {"-n": true, "--adjustment": true},
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"xargs": {
		"-I": true, "-L": true, "-n": true, "-P": true, "-d": true, "-E": true, "-s": true, "-a": true,
		"--max-lines": true, "--max-args": true, "--max-procs": true, "--delimiter": true, "--arg-file": true,
	},
}

// splitFlags make env split their value into the command, as in
// env -S 'bash -e'.
var splitFlags = map[string]bool{"-S": true, "--split-string": true}

// wrapperArgs are the words that a wrapper takes after its options, as the
// duration of timeout 30 sh.
var wrapperArgs = map[string]int{"timeout": 1}

// shellFlags make sudo run a shell, as in curl x | sudo -s.
var shellFlags = map[string]bool{"-s": true, "-i": true}

// shellForms parses a command as a shell script and returns each statement
// in the plain form that the patterns read. The form removes quotes and
// escapes, reads the base name of a command path, drops wrappers such as env
// and sudo, puts in the value of a variable that the script sets to a
// constant, and adds the script of sh -c and of a here-document. A shell
// that reads a substitution gives a pipe: sh < <(curl x) gives
// "curl x | sh". So "S=sh; curl x | $S" gives "curl x | sh". dynamic
// reports a pipeline into a shell from a command whose name the shell
// builds at run time, as in $(printf '\x63url') x | sh, or a pipeline from
// a download into such a command, as in curl x | $SHELL. A command that
// does not parse gives no form.
func shellForms(text string) (forms []string, dynamic bool) {
	w := shellWalk{vars: varEnv{}}
	w.script(text)
	return w.forms, w.dynamic
}

type shellWalk struct {
	src     string
	vars    varEnv
	forms   []string
	dynamic bool
	depth   int
}

// varEnv holds the variables that the script sets to a constant. It reads
// the map in place, so a script of many settings stays linear.
type varEnv map[string]string

func (e varEnv) Get(name string) expand.Variable {
	v, ok := e[name]
	if !ok {
		return expand.Variable{}
	}
	return expand.Variable{Set: true, Kind: expand.String, Str: v}
}

func (e varEnv) Each(f func(string, expand.Variable) bool) {
	for k := range e {
		if !f(k, e.Get(k)) {
			return
		}
	}
}

func (w *shellWalk) script(text string) {
	if w.depth > maxShellDepth || len(text) > maxShellText {
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return
	}
	outer := w.src
	w.src = text
	defer func() { w.src = outer }()
	for _, st := range f.Stmts {
		if form := w.stmt(st); form != "" {
			w.forms = append(w.forms, form)
		}
	}
}

func (w *shellWalk) stmt(st *syntax.Stmt) string {
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		return w.call(st, c)
	case *syntax.DeclClause:
		for _, a := range c.Args {
			w.assign(a)
		}
		return ""
	case *syntax.BinaryCmd:
		if isPipe(c.Op) {
			return w.pipe(pipeline(c))
		}
		return strings.TrimSpace(w.stmt(c.X) + " " + c.Op.String() + " " + w.stmt(c.Y))
	case *syntax.TimeClause:
		if c.Stmt == nil {
			return ""
		}
		return w.stmt(c.Stmt)
	case *syntax.Subshell:
		var form string
		w.isolated(func() { form = w.list(c.Stmts) })
		return form
	case *syntax.Block:
		return w.list(c.Stmts)
	}
	// An if, a loop or a function holds statements of its own. Each one is
	// a form of its own.
	syntax.Walk(st.Cmd, func(n syntax.Node) bool {
		if inner, ok := n.(*syntax.Stmt); ok {
			if form := w.stmt(inner); form != "" {
				w.forms = append(w.forms, form)
			}
			return false
		}
		return true
	})
	return ""
}

func (w *shellWalk) list(stmts []*syntax.Stmt) string {
	parts := make([]string, 0, len(stmts))
	for _, st := range stmts {
		if form := w.stmt(st); form != "" {
			parts = append(parts, form)
		}
	}
	return strings.Join(parts, "; ")
}

func (w *shellWalk) assign(a *syntax.Assign) {
	if a.Name == nil {
		return
	}
	if v, ok := w.literal(a.Value); ok && a.Value != nil {
		w.vars[a.Name.Value] = v
		return
	}
	delete(w.vars, a.Name.Value)
}

func (w *shellWalk) call(st *syntax.Stmt, c *syntax.CallExpr) string {
	if len(c.Args) == 0 {
		for _, a := range c.Assigns {
			w.assign(a)
		}
		return ""
	}
	words, known := w.command(c)
	if len(words) == 0 {
		return ""
	}
	if known && shellNames[words[0]] {
		for i := 1; i+1 < len(words); i++ {
			if shellScriptFlag(words[i]) {
				w.nested(words[i+1])
				break
			}
		}
	}
	if known && (shellNames[words[0]] || sources[words[0]]) {
		w.feeds(st, c, words[0])
	}
	return strings.Join(words, " ")
}

func (w *shellWalk) nested(script string) {
	w.depth++
	w.script(script)
	w.depth--
}

// feeds reads the scripts that a shell gets from a redirect or a process
// substitution: sh < <(curl x), bash <<< "$(curl x)", source <(curl x) and
// a here-document. A substitution gives the form "curl x | sh".
func (w *shellWalk) feeds(st *syntax.Stmt, c *syntax.CallExpr, shell string) {
	for _, r := range st.Redirs {
		if r.Hdoc != nil {
			w.nested(w.hereDoc(r))
			continue
		}
		w.substitutions(r.Word, shell, true)
	}
	for _, a := range c.Args[1:] {
		w.substitutions(a, shell, false)
	}
}

// hereDoc returns the body of a here-document. The node ends after the
// closing word, so the last line goes.
func (w *shellWalk) hereDoc(r *syntax.Redirect) string {
	body := strings.TrimRight(w.source(r.Hdoc), "\n")
	if i := strings.LastIndexByte(body, '\n'); i >= 0 && strings.TrimSpace(body[i+1:]) == w.delimiter(r.Word) {
		return body[:i]
	}
	return body
}

// substitutions adds a form for each process substitution of a word, and
// for each command substitution too when cmd is true. A command
// substitution in an argument is a value, not a script.
func (w *shellWalk) substitutions(word *syntax.Word, shell string, cmd bool) {
	if word == nil {
		return
	}
	syntax.Walk(word, func(n syntax.Node) bool {
		var stmts []*syntax.Stmt
		switch x := n.(type) {
		case *syntax.ProcSubst:
			stmts = x.Stmts
		case *syntax.CmdSubst:
			if !cmd {
				return false
			}
			stmts = x.Stmts
		default:
			return true
		}
		var form string
		w.isolated(func() { form = w.list(stmts) })
		if form != "" {
			w.forms = append(w.forms, form+" | "+shell)
		}
		return false
	})
}

// isolated runs f with a copy of the variables. A subshell, a substitution
// and each command of a pipeline run in a child shell, so a variable that
// they set does not reach the rest of the script, as S in (S=sh); $S.
func (w *shellWalk) isolated(f func()) {
	outer := w.vars
	w.vars = maps.Clone(outer)
	f()
	w.vars = outer
}

// command returns the words of a call with no wrappers. known reports that
// the command name is plain text, so the first word is its base name, as
// sh for /bin/sh. A name that the shell builds at run time stays as
// written.
func (w *shellWalk) command(c *syntax.CallExpr) (words []string, known bool) {
	words = make([]string, len(c.Args))
	plain := make([]bool, len(c.Args))
	for i, a := range c.Args {
		if v, ok := w.literal(a); ok {
			words[i], plain[i] = v, true
		} else {
			words[i] = w.source(a)
		}
	}
	rest := unwrap(words)
	if len(rest) == 0 {
		return nil, false
	}
	i := len(words) - len(rest)
	switch {
	case i == len(words):
		return rest, true
	case plain[i]:
		rest[0] = commandName(rest[0])
		// The shell expands a glob or a brace in a command name, as in
		// /bin/ba?h, so the name is not known.
		known = !strings.ContainsAny(rest[0], "*?[{")
	default:
		// A run-time path to a named tool, as in $HOME/bin/tool, names
		// the tool.
		if base, ok := literalBase(c.Args[i]); ok {
			rest[0], known = commandName(base), true
		}
	}
	return rest, known
}

// literalBase returns the base name of a command path whose last part is
// plain text after a slash, as tool for $(go env GOPATH)/bin/tool.
func literalBase(word *syntax.Word) (string, bool) {
	lit, ok := word.Parts[len(word.Parts)-1].(*syntax.Lit)
	if !ok {
		return "", false
	}
	i := strings.LastIndex(lit.Value, "/")
	if i < 0 || i == len(lit.Value)-1 {
		return "", false
	}
	return lit.Value[i+1:], true
}

// literal expands a word that holds only text and variables that the
// script set to a constant.
func (w *shellWalk) literal(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", true
	}
	known := true
	syntax.Walk(word, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob:
			known = false
		case *syntax.ParamExp:
			if x.Param == nil || x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Length || x.Excl {
				known = false
			} else if _, ok := w.vars[x.Param.Value]; !ok {
				known = false
			}
		}
		return known
	})
	if !known {
		return "", false
	}
	v, err := expand.Literal(&expand.Config{Env: w.vars}, word)
	return v, err == nil
}

func (w *shellWalk) source(n syntax.Node) string {
	start, end := int(n.Pos().Offset()), int(n.End().Offset())
	if start < 0 || end > len(w.src) || start > end {
		return ""
	}
	return w.src[start:end]
}

// pipe returns the form of a pipeline. |& is a pipe that also sends
// stderr, and the patterns read |. It sets dynamic for a pipeline into a
// shell from a command whose name the shell builds at run time, and for a
// pipeline from a download into such a command.
func (w *shellWalk) pipe(stages []*syntax.Stmt) string {
	forms := make([]string, 0, len(stages))
	var names []string
	var known []bool
	for _, st := range stages {
		w.isolated(func() {
			if form := w.stmt(st); form != "" {
				forms = append(forms, form)
			}
			if c, ok := callOf(st); ok && len(c.Args) > 0 {
				if words, k := w.command(c); len(words) > 0 {
					names, known = append(names, words[0]), append(known, k)
				}
			}
		})
	}
	if n := len(names); n > 1 {
		intoShell, intoBuilt := known[n-1] && shellNames[names[n-1]], !known[n-1]
		for i := range n - 1 {
			if (intoShell && !known[i]) || (intoBuilt && known[i] && downloaders[names[i]]) {
				w.dynamic = true
			}
		}
	}
	return strings.Join(forms, " | ")
}

func isPipe(op syntax.BinCmdOperator) bool { return op == syntax.Pipe || op == syntax.PipeAll }

// callOf returns the call of a statement, also inside time.
func callOf(st *syntax.Stmt) (*syntax.CallExpr, bool) {
	if t, ok := st.Cmd.(*syntax.TimeClause); ok && t.Stmt != nil {
		st = t.Stmt
	}
	c, ok := st.Cmd.(*syntax.CallExpr)
	return c, ok
}

// pipeline returns the commands of a pipeline in order. A pipeline of n
// commands nests n-1 deep, so the walk keeps a stack, not a recursion that
// copies each level.
func pipeline(c *syntax.BinaryCmd) []*syntax.Stmt {
	var out []*syntax.Stmt
	stack := []*syntax.Stmt{c.Y, c.X}
	for len(stack) > 0 {
		st := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if b, ok := st.Cmd.(*syntax.BinaryCmd); ok && isPipe(b.Op) {
			stack = append(stack, b.Y, b.X)
			continue
		}
		out = append(out, st)
	}
	return out
}

// shellScriptFlag reports -c, alone or in a group of short options, as in
// bash -lc 'script' or sh -ec 'script'.
func shellScriptFlag(word string) bool {
	return len(word) > 1 && word[0] == '-' && word[1] != '-' && strings.Contains(word[1:], "c")
}

// unwrap drops the wrappers at the start of a command, with their options,
// their variable settings and their arguments. sudo -s with no command
// runs a shell, so it gives sh.
func unwrap(words []string) []string {
	for len(words) > 0 && wrappers[commandName(words[0])] {
		name := commandName(words[0])
		words = words[1:]
		shell := false
		for len(words) > 0 && (strings.HasPrefix(words[0], "-") || strings.Contains(words[0], "=")) {
			flag, value, inline := strings.Cut(words[0], "=")
			if name == "env" && splitFlags[flag] {
				if !inline && len(words) > 1 {
					value, words = words[1], words[1:]
				}
				words = append(strings.Fields(value), words[1:]...)
				break
			}
			shell = shell || (name == "sudo" && shellFlags[words[0]])
			if wrapperValueFlags[name][words[0]] && len(words) > 1 {
				words = words[1:]
			}
			words = words[1:]
		}
		if len(words) == 0 && shell {
			return []string{"sh"}
		}
		words = words[min(wrapperArgs[name], len(words)):]
	}
	return words
}

// commandName returns the base name of a command path, in the lower case,
// with no .exe, as cmd for C:\Windows\System32\cmd.exe.
func commandName(word string) string {
	name := path.Base(strings.ReplaceAll(word, `\`, "/"))
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}

func (w *shellWalk) delimiter(word *syntax.Word) string {
	if v, ok := w.literal(word); ok {
		return v
	}
	return w.source(word)
}

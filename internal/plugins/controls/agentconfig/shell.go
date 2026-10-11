package agentconfig

import (
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
	"cmd": true, "powershell": true, "pwsh": true,
}

// wrappers run the command that follows their own options, as in
// env X=1 sh or sudo -u root sh.
var wrappers = map[string]bool{
	"env": true, "sudo": true, "doas": true, "exec": true, "command": true,
	"nohup": true, "nice": true, "time": true, "busybox": true,
}

// wrapperValueFlags are the wrapper options that take the next word.
var wrapperValueFlags = map[string]bool{"-u": true, "-g": true, "-C": true, "-n": true, "-p": true, "-U": true}

// shellForms parses a command as a shell script and returns each statement
// in the plain form that the patterns read. The form removes quotes and
// escapes, reads the base name of a command path, drops wrappers such as env
// and sudo, puts in the value of a variable that the script sets to a
// constant, and adds the script of sh -c. So "S=sh; curl x | $S" gives
// "curl x | sh". dynamic reports a pipeline into a shell whose first command
// name the shell builds at run time, as in $(printf '\x63url') x | sh. A
// command that does not parse gives no form.
func shellForms(text string) (forms []string, dynamic bool) {
	w := shellWalk{vars: map[string]string{}}
	w.script(text)
	return w.forms, w.dynamic
}

type shellWalk struct {
	src     string
	vars    map[string]string
	forms   []string
	dynamic bool
	depth   int
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
		return w.call(c)
	case *syntax.DeclClause:
		for _, a := range c.Args {
			w.assign(a)
		}
		return ""
	case *syntax.BinaryCmd:
		x, y := w.stmt(c.X), w.stmt(c.Y)
		if (c.Op == syntax.Pipe || c.Op == syntax.PipeAll) && w.dynamicInto(c) {
			w.dynamic = true
		}
		op := c.Op.String()
		if c.Op == syntax.PipeAll {
			// |& is a pipe that also sends stderr. The patterns read |.
			op = "|"
		}
		return strings.TrimSpace(x + " " + op + " " + y)
	case *syntax.Subshell:
		return w.list(c.Stmts)
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

func (w *shellWalk) call(c *syntax.CallExpr) string {
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
			if words[i] == "-c" {
				w.depth++
				w.script(words[i+1])
				w.depth--
				break
			}
		}
	}
	return strings.Join(words, " ")
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
	known = plain[len(words)-len(rest)]
	if known {
		rest[0] = commandName(rest[0])
	}
	return rest, known
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
	env := make([]string, 0, len(w.vars))
	for k, v := range w.vars {
		env = append(env, k+"="+v)
	}
	v, err := expand.Literal(&expand.Config{Env: expand.ListEnviron(env...)}, word)
	return v, err == nil
}

func (w *shellWalk) source(n syntax.Node) string {
	start, end := int(n.Pos().Offset()), int(n.End().Offset())
	if start < 0 || end > len(w.src) || start > end {
		return ""
	}
	return w.src[start:end]
}

// dynamicInto reports a pipeline whose last command is a shell and one of
// whose commands has a name that the shell builds at run time.
func (w *shellWalk) dynamicInto(c *syntax.BinaryCmd) bool {
	stages := pipeline(c)
	last, ok := stages[len(stages)-1].Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	if words, known := w.command(last); !known || !shellNames[words[0]] {
		return false
	}
	for _, st := range stages[:len(stages)-1] {
		call, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		if _, known := w.command(call); !known {
			return true
		}
	}
	return false
}

// pipeline returns the commands of a pipeline in order.
func pipeline(c *syntax.BinaryCmd) []*syntax.Stmt {
	var out []*syntax.Stmt
	for _, st := range []*syntax.Stmt{c.X, c.Y} {
		if b, ok := st.Cmd.(*syntax.BinaryCmd); ok && (b.Op == syntax.Pipe || b.Op == syntax.PipeAll) {
			out = append(out, pipeline(b)...)
			continue
		}
		out = append(out, st)
	}
	return out
}

// unwrap drops the wrappers at the start of a command, with their options
// and their variable settings.
func unwrap(words []string) []string {
	for len(words) > 0 && wrappers[commandName(words[0])] {
		words = words[1:]
		for len(words) > 0 && (strings.HasPrefix(words[0], "-") || strings.Contains(words[0], "=")) {
			if wrapperValueFlags[words[0]] && len(words) > 1 {
				words = words[1:]
			}
			words = words[1:]
		}
	}
	return words
}

// commandName returns the base name of a command path, in the lower case,
// with no .exe, as cmd for C:\Windows\System32\cmd.exe.
func commandName(word string) string {
	name := path.Base(strings.ReplaceAll(word, `\`, "/"))
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}

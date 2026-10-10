package agentconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"gopkg.in/yaml.v3"
)

// command is one shell command that an editor, an agent or a git hook
// runs.
type command struct {
	// name tells the command apart in its file, for example a task label.
	name string
	text string
	line int
	// onOpen is an editor task that runs when the folder opens.
	onOpen bool
	// hidden is an editor task that hides its terminal and its output.
	hidden bool
}

// setting is one editor setting that turns off a safety check.
type setting struct {
	key   string
	title string
	line  int
}

// server is one MCP server of a config file.
type server struct {
	name    string
	command string
	url     string
	line    int
}

// The parsers decode into generic values and read each field with a type
// check. A typed decode stops at the first value of a wrong type, so one
// bad value would hide the commands of the whole file. Map keys also match
// exactly, as they do in the editor. encoding/json matches struct fields
// with no case, so a decoy "COMMAND" key would win over "command".
type object = map[string]any

// objectOf returns v as an object. yaml.v3 decodes a mapping with a key
// that is not a string, such as 1:, to map[any]any, so the keys become
// strings.
func objectOf(v any) object {
	switch o := v.(type) {
	case map[string]any:
		return o
	case map[any]any:
		out := make(object, len(o))
		for k, e := range o {
			out[fmt.Sprint(k)] = e
		}
		return out
	}
	return nil
}

func listOf(v any) []any { l, _ := v.([]any); return l }

func stringOf(v any) string { s, _ := v.(string); return s }

// sortedKeys returns the keys of o in order.
func sortedKeys(o object) []string {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseError is a syntax error with its line in the file.
type parseError struct {
	line int
	err  error
}

func (e *parseError) Error() string { return e.err.Error() }

func (e *parseError) Unwrap() error { return e.err }

// errorLine returns the line of a parse error, or 1.
func errorLine(err error) int {
	var pe *parseError
	if errors.As(err, &pe) {
		return pe.line
	}
	return 1
}

var bom = []byte("\xEF\xBB\xBF")

// utf8Text returns a UTF-16 file with a byte order mark as UTF-8. The
// editors read such a file, so vet reads it too. Other data comes back as
// it is.
func utf8Text(data []byte) []byte {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		order = binary.BigEndian
	default:
		return data
	}
	units := make([]uint16, 0, len(data)/2)
	for i := 2; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16(data[i:]))
	}
	return []byte(string(utf16.Decode(units)))
}

// stripJSONC removes the byte order mark, the comments and the trailing
// commas of a JSON with comments file, such as the VS Code and devcontainer
// files. It keeps each line break, so a line in the result is the same line
// in the file.
func stripJSONC(data []byte) []byte {
	return stripTrailingCommas(stripComments(bytes.TrimPrefix(data, bom)))
}

// scanJSON calls each for each byte outside a string, and copies each byte
// of a string as it is. each returns how many bytes it took.
func scanJSON(data []byte, each func(out *bytes.Buffer, i int) int) []byte {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}
		i += each(&out, i) - 1
	}
	return out.Bytes()
}

func stripComments(data []byte) []byte {
	return scanJSON(data, func(out *bytes.Buffer, i int) int {
		switch {
		case bytes.HasPrefix(data[i:], []byte("//")):
			end := bytes.IndexByte(data[i:], '\n')
			if end < 0 {
				return len(data) - i
			}
			return end
		case bytes.HasPrefix(data[i:], []byte("/*")):
			end := bytes.Index(data[i+2:], []byte("*/"))
			n := len(data) - i
			if end >= 0 {
				n = end + 4
			}
			out.Write(bytes.Repeat([]byte("\n"), bytes.Count(data[i:i+n], []byte("\n"))))
			return n
		}
		out.WriteByte(data[i])
		return 1
	})
}

func stripTrailingCommas(data []byte) []byte {
	return scanJSON(data, func(out *bytes.Buffer, i int) int {
		if data[i] == ',' {
			rest := bytes.TrimLeft(data[i+1:], " \t\r\n")
			if len(rest) > 0 && (rest[0] == '}' || rest[0] == ']') {
				return 1
			}
		}
		out.WriteByte(data[i])
		return 1
	})
}

// decodeJSONC decodes a JSON with comments file into a generic value. An
// empty file holds nothing and gives nil.
func decodeJSONC(data []byte) (any, error) {
	clean := stripJSONC(data)
	if len(bytes.TrimSpace(clean)) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(clean, &v); err != nil {
		line := 1
		var se *json.SyntaxError
		if errors.As(err, &se) && se.Offset > 0 && se.Offset <= int64(len(clean)) {
			line = bytes.Count(clean[:se.Offset], []byte("\n")) + 1
		}
		return nil, &parseError{line: line, err: err}
	}
	return v, nil
}

var yamlLine = regexp.MustCompile(`^yaml: line (\d+):`)

// decodeYAML decodes a YAML file into a generic value.
func decodeYAML(data []byte) (any, error) {
	var v any
	if err := yaml.Unmarshal(data, &v); err != nil {
		line := 1
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			if n, convErr := strconv.Atoi(m[1]); convErr == nil {
				line = n
			}
		}
		return nil, &parseError{line: line, err: err}
	}
	return v, nil
}

// lineOf returns the line of the first occurrence of the JSON form of s,
// or of s itself, or 1.
func lineOf(data []byte, s string) int {
	if s == "" {
		return 1
	}
	b, err := json.Marshal(s)
	if err == nil {
		if i := bytes.Index(data, b[1:len(b)-1]); i >= 0 {
			return bytes.Count(data[:i], []byte("\n")) + 1
		}
	}
	if i := bytes.Index(data, []byte(s)); i >= 0 {
		return bytes.Count(data[:i], []byte("\n")) + 1
	}
	// A command list such as ["npm", "ci"] joins to a text that the file
	// does not hold. Its first word is on the line of the list.
	if f := strings.Fields(s); len(f) > 1 {
		return lineOf(data, `"`+f[0]+`"`)
	}
	return 1
}

// commandText joins a command and its arguments. A command can be a
// string, a list of strings, or, in devcontainer.json, a map of named
// commands.
func commandText(v any) []string {
	switch c := v.(type) {
	case string:
		if strings.TrimSpace(c) == "" {
			return nil
		}
		return []string{c}
	case []any:
		var parts []string
		for _, p := range c {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return nil
		}
		return []string{strings.Join(parts, " ")}
	case map[string]any:
		var out []string
		for _, k := range sortedKeys(c) {
			out = append(out, commandText(c[k])...)
		}
		return out
	}
	return nil
}

// taskWord is one word of a task command or of its args: a string, or a
// quoted string as {"value": "...", "quoting": "strong"}.
func taskWord(v any) string {
	if o := objectOf(v); o != nil {
		v = o["value"]
	}
	switch w := v.(type) {
	case string:
		return w
	case []any:
		parts := make([]string, 0, len(w))
		for _, p := range w {
			if s := stringOf(p); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// taskText joins the command and the args of a task, or of one OS block of
// a task.
func taskText(t object) (text, first string) {
	first = taskWord(t["command"])
	if script := stringOf(t["script"]); strings.TrimSpace(first) == "" && script != "" {
		// An npm task runs a script of package.json.
		first = script
		return "npm run " + script, first
	}
	if strings.TrimSpace(first) == "" {
		return "", ""
	}
	// The shell of a task runs the command with its own arguments, which
	// can hold the payload.
	shell := objectOf(objectOf(t["options"])["shell"])
	words := []string{}
	if exe := stringOf(shell["executable"]); exe != "" {
		words = append(words, exe)
		for _, a := range listOf(shell["args"]) {
			words = append(words, stringOf(a))
		}
	}
	words = append(words, first)
	for _, a := range listOf(t["args"]) {
		if w := taskWord(a); w != "" {
			words = append(words, w)
		}
	}
	return strings.Join(words, " "), first
}

// hiddenTask reports a task that does not show its terminal and also hides
// it in a second way: out of the task list, with no echo of the command, or
// with the terminal closed at the end. A watch task can set reveal: never
// or silent alone. The PolinRider tasks set all of them.
func hiddenTask(t object) bool {
	p := objectOf(t["presentation"])
	if r := stringOf(p["reveal"]); r != "never" && r != "silent" {
		return false
	}
	hide, _ := t["hide"].(bool)
	echo, hasEcho := p["echo"].(bool)
	closes, _ := p["close"].(bool)
	return hide || (hasEcho && !echo) || closes
}

// taskOSes are the OS blocks of a task, each with its own command.
var taskOSes = []string{"windows", "osx", "linux"}

// mergedKeys are the task keys whose objects the editor merges key by key
// with the outer level, in place of a full replace.
var mergedKeys = map[string]bool{"options": true, "shell": true, "env": true, "presentation": true}

// overlay returns a copy of base with the keys of top on top, as the editor
// merges an OS block over a task and a task over the root of tasks.json.
// The args of both levels add up, outer first.
func overlay(base, top object) object {
	out := maps.Clone(base)
	if out == nil {
		out = object{}
	}
	for k, v := range top {
		if sub, outer := objectOf(v), objectOf(out[k]); mergedKeys[k] && sub != nil && outer != nil {
			v = overlay(outer, sub)
		}
		if k == "args" {
			v = append(slices.Clone(listOf(out[k])), listOf(v)...)
		}
		out[k] = v
	}
	return out
}

// inherited returns the keys of a root object or a root OS block that each
// task of tasks.json inherits. A task with no command runs the root command.
func inherited(o object) object {
	out := object{}
	for _, k := range []string{"command", "args", "options", "presentation"} {
		if v, ok := o[k]; ok {
			out[k] = v
		}
	}
	return out
}

// editorTasks reads the shell and process tasks of .vscode/tasks.json. The
// editor runs each task with the options and presentation of the root, and
// with the OS block of the developer merged on top. So vet reads one
// command for each OS whose merged task differs from the plain task.
func editorTasks(data []byte) ([]command, error) {
	doc, err := decodeJSONC(data)
	if err != nil {
		return nil, err
	}
	root := objectOf(doc)
	base := inherited(root)
	var out []command
	for i, v := range listOf(root["tasks"]) {
		if len(out) > maxCommands {
			break
		}
		t := objectOf(v)
		if t == nil {
			continue
		}
		name := stringOf(t["label"])
		if name == "" {
			name = fmt.Sprintf("task %d", i+1)
		}
		onOpen := stringOf(objectOf(t["runOptions"])["runOn"]) == "folderOpen"
		seen := map[command]bool{}
		add := func(suffix string, task object) {
			text, first := taskText(task)
			if text == "" {
				return
			}
			c := command{text: text, onOpen: onOpen, hidden: hiddenTask(task)}
			if seen[c] {
				return
			}
			seen[c] = true
			c.name, c.line = name+suffix, lineOf(data, first)
			out = append(out, c)
		}
		add("", overlay(base, t))
		for _, osName := range taskOSes {
			rootOS, taskOS := objectOf(root[osName]), objectOf(t[osName])
			if rootOS == nil && taskOS == nil {
				continue
			}
			add(" ("+osName+")", overlay(overlay(overlay(base, inherited(rootOS)), t), taskOS))
		}
	}
	return out, nil
}

// claudeHooks reads the hook commands and the status line command of
// .claude/settings.json.
func claudeHooks(data []byte) ([]command, error) {
	doc, err := decodeJSONC(data)
	if err != nil {
		return nil, err
	}
	root := objectOf(doc)
	hooks := objectOf(root["hooks"])
	var out []command
	for _, event := range sortedKeys(hooks) {
		if len(out) > maxCommands {
			break
		}
		for _, mv := range listOf(hooks[event]) {
			m := objectOf(mv)
			for _, hv := range listOf(m["hooks"]) {
				c := stringOf(objectOf(hv)["command"])
				if strings.TrimSpace(c) == "" {
					continue
				}
				name := event
				if matcher := stringOf(m["matcher"]); matcher != "" {
					name += " " + matcher
				}
				out = append(out, command{name: name, text: c, line: lineOf(data, c)})
			}
		}
	}
	if c := strings.TrimSpace(stringOf(objectOf(root["statusLine"])["command"])); c != "" {
		out = append(out, command{name: "statusLine", text: c, line: lineOf(data, c)})
	}
	return out, nil
}

var lifecycle = []string{"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}

// devContainer reads the lifecycle commands of devcontainer.json.
func devContainer(data []byte) ([]command, error) {
	doc, err := decodeJSONC(data)
	if err != nil {
		return nil, err
	}
	root := objectOf(doc)
	var out []command
	for _, key := range lifecycle {
		for _, text := range commandText(root[key]) {
			out = append(out, command{name: key, text: text, line: lineOf(data, text)})
		}
	}
	return out, nil
}

// huskySource is the line of a husky v8 hook that sources the husky helper.
var huskySource = regexp.MustCompile(`^(\.|source)\s+["']?\$\(dirname\b.*_/husky\.sh`)

// gitHook reads the command lines of a git hook script. A line that ends
// with a backslash goes on in the next line, so the two are one command.
func gitHook(data []byte) []command {
	var out []command
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines) && len(out) <= maxCommands; i++ {
		start := i
		l := strings.TrimSpace(lines[i])
		for strings.HasSuffix(l, "\\") && i+1 < len(lines) {
			i++
			l = strings.TrimSuffix(l, "\\") + " " + strings.TrimSpace(lines[i])
		}
		if l == "" || strings.HasPrefix(l, "#") || huskySource.MatchString(l) {
			continue
		}
		out = append(out, command{name: "hook", text: l, line: start + 1})
	}
	return out
}

// lefthook reads the run commands of lefthook.yml. A top-level key that is
// not a hook, such as min_version or colors, holds no command.
func lefthook(data []byte) ([]command, error) {
	doc, err := decodeYAML(data)
	if err != nil {
		return nil, err
	}
	root := objectOf(doc)
	var out []command
	for _, h := range sortedKeys(root) {
		if len(out) > maxCommands {
			break
		}
		hook := objectOf(root[h])
		cmds := objectOf(hook["commands"])
		for _, n := range sortedKeys(cmds) {
			if run := strings.TrimSpace(stringOf(objectOf(cmds[n])["run"])); run != "" {
				out = append(out, command{name: h + " " + n, text: run, line: lineOf(data, run)})
			}
		}
		for i, jv := range listOf(hook["jobs"]) {
			j := objectOf(jv)
			if run := strings.TrimSpace(stringOf(j["run"])); run != "" {
				name := stringOf(j["name"])
				if name == "" {
					name = fmt.Sprintf("job %d", i+1)
				}
				out = append(out, command{name: h + " " + name, text: run, line: lineOf(data, run)})
			}
		}
	}
	return out, nil
}

// mcpServers reads the servers of an MCP config: mcpServers in the agent
// files, servers in .vscode/mcp.json.
func mcpServers(data []byte) ([]server, error) {
	doc, err := decodeJSONC(data)
	if err != nil {
		return nil, err
	}
	root := objectOf(doc)
	all := object{}
	for _, key := range []string{"servers", "mcpServers"} {
		for n, e := range objectOf(root[key]) {
			all[n] = e
		}
	}
	var out []server
	for _, n := range sortedKeys(all) {
		if len(out) > maxCommands {
			break
		}
		e := objectOf(all[n])
		url := ""
		for _, key := range []string{"url", "serverUrl", "httpUrl"} {
			if url == "" {
				url = stringOf(e[key])
			}
		}
		words := []string{stringOf(e["command"])}
		for _, a := range listOf(e["args"]) {
			words = append(words, stringOf(a))
		}
		cmd := strings.TrimSpace(strings.Join(words, " "))
		out = append(out, server{name: n, command: cmd, url: url, line: lineOf(data, n)})
	}
	return out, nil
}

// unsafeSettings are the editor settings that turn off a safety check, with
// the values that do it and why.
var unsafeSettings = []struct {
	key    string
	unsafe func(v any) bool
	title  string
}{
	{"task.allowAutomaticTasks", func(v any) bool { return v == "on" || v == true }, "Setting task.allowAutomaticTasks lets a folder-open task run with no prompt"},
	{"terminal.integrated.hideOnStartup", func(v any) bool { return v == "always" }, "Setting terminal.integrated.hideOnStartup hides the terminal of a task"},
	{"security.workspace.trust.enabled", func(v any) bool { return v == false }, "Setting security.workspace.trust.enabled turns off workspace trust"},
}

// editorSettings reads the settings of an editor settings.json that turn
// off a safety check.
func editorSettings(data []byte) ([]setting, error) {
	doc, err := decodeJSONC(data)
	if err != nil {
		return nil, err
	}
	root := objectOf(doc)
	var out []setting
	for _, u := range unsafeSettings {
		if v, ok := root[u.key]; ok && u.unsafe(v) {
			out = append(out, setting{key: u.key, title: u.title, line: lineOf(data, `"`+u.key+`"`)})
		}
	}
	return out, nil
}

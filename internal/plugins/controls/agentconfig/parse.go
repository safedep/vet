package agentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

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
}

// server is one MCP server of a config file.
type server struct {
	name    string
	command string
	url     string
	line    int
}

// stripJSONC removes the comments and the trailing commas of a JSON with
// comments file, such as the VS Code and devcontainer files.
func stripJSONC(data []byte) []byte {
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
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				i = len(data)
				continue
			}
			// Keep the line breaks, so the line numbers stay right.
			out.Write(bytes.Repeat([]byte("\n"), bytes.Count(data[i:i+2+end+2], []byte("\n"))))
			i += 2 + end + 1
		case c == ',':
			j := i + 1
			for j < len(data) && strings.ContainsRune(" \t\r\n", rune(data[j])) {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

// errorLine returns the line of a JSON syntax error in a JSON with comments
// file, or 1. stripJSONC keeps the line breaks, so the offset in the
// stripped data gives the line in the file.
func errorLine(data []byte, err error) int {
	var se *json.SyntaxError
	if !errors.As(err, &se) {
		return 1
	}
	clean := stripJSONC(data)
	if se.Offset <= 0 || se.Offset > int64(len(clean)) {
		return 1
	}
	return bytes.Count(clean[:se.Offset], []byte("\n")) + 1
}

// decodeJSONC decodes a JSON with comments file. An empty file holds
// nothing and leaves v as it is.
func decodeJSONC(data []byte, v any) error {
	clean := stripJSONC(data)
	if len(bytes.TrimSpace(clean)) == 0 {
		return nil
	}
	return json.Unmarshal(clean, v)
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
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, commandText(c[k])...)
		}
		return out
	}
	return nil
}

// taskCommand is the command part of a task, or of one OS block of it.
type taskCommand struct {
	Command any   `json:"command"`
	Args    []any `json:"args"`
}

// text joins the command and its arguments, or gives "".
func (c taskCommand) text() string {
	texts := commandText(c.Command)
	if len(texts) == 0 {
		return ""
	}
	if args := commandText(c.Args); len(args) > 0 {
		return texts[0] + " " + args[0]
	}
	return texts[0]
}

// editorTasks reads the shell and process tasks of .vscode/tasks.json. A
// task can set its own command in each OS block, and the editor runs the
// one of the OS of the developer.
func editorTasks(data []byte) ([]command, error) {
	var doc struct {
		Tasks []struct {
			taskCommand
			Label      string       `json:"label"`
			Windows    *taskCommand `json:"windows"`
			OSX        *taskCommand `json:"osx"`
			Linux      *taskCommand `json:"linux"`
			RunOptions struct {
				RunOn string `json:"runOn"`
			} `json:"runOptions"`
		} `json:"tasks"`
	}
	if err := decodeJSONC(data, &doc); err != nil {
		return nil, err
	}
	var out []command
	for i, t := range doc.Tasks {
		name := t.Label
		if name == "" {
			name = fmt.Sprintf("task %d", i+1)
		}
		onOpen := t.RunOptions.RunOn == "folderOpen"
		blocks := []struct {
			suffix string
			c      *taskCommand
		}{{"", &t.taskCommand}, {" (windows)", t.Windows}, {" (osx)", t.OSX}, {" (linux)", t.Linux}}
		for _, b := range blocks {
			if b.c == nil {
				continue
			}
			if text := b.c.text(); text != "" {
				out = append(out, command{name: name + b.suffix, text: text, line: lineOf(data, firstText(b.c.Command)), onOpen: onOpen})
			}
		}
	}
	return out, nil
}

// firstText returns the first command text of v, or "".
func firstText(v any) string {
	if texts := commandText(v); len(texts) > 0 {
		return texts[0]
	}
	return ""
}

// claudeHooks reads the hook commands and the status line command of
// .claude/settings.json.
func claudeHooks(data []byte) ([]command, error) {
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
		StatusLine struct {
			Command string `json:"command"`
		} `json:"statusLine"`
	}
	if err := decodeJSONC(data, &doc); err != nil {
		return nil, err
	}
	events := make([]string, 0, len(doc.Hooks))
	for e := range doc.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	var out []command
	for _, e := range events {
		for _, m := range doc.Hooks[e] {
			for _, h := range m.Hooks {
				if strings.TrimSpace(h.Command) == "" {
					continue
				}
				name := e
				if m.Matcher != "" {
					name += " " + m.Matcher
				}
				out = append(out, command{name: name, text: h.Command, line: lineOf(data, h.Command)})
			}
		}
	}
	if c := strings.TrimSpace(doc.StatusLine.Command); c != "" {
		out = append(out, command{name: "statusLine", text: c, line: lineOf(data, c)})
	}
	return out, nil
}

var lifecycle = []string{"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}

// devContainer reads the lifecycle commands of devcontainer.json.
func devContainer(data []byte) ([]command, error) {
	var doc map[string]any
	if err := decodeJSONC(data, &doc); err != nil {
		return nil, err
	}
	var out []command
	for _, key := range lifecycle {
		for _, text := range commandText(doc[key]) {
			out = append(out, command{name: key, text: text, line: lineOf(data, text)})
		}
	}
	return out, nil
}

// gitHook reads the command lines of a husky hook script.
func gitHook(data []byte) []command {
	var out []command
	for i, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.Contains(l, "husky.sh") {
			continue
		}
		out = append(out, command{name: "hook", text: l, line: i + 1})
	}
	return out
}

// lefthook reads the run commands of lefthook.yml.
func lefthook(data []byte) ([]command, error) {
	var doc map[string]struct {
		Commands map[string]struct {
			Run string `yaml:"run"`
		} `yaml:"commands"`
		Jobs []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	hooks := make([]string, 0, len(doc))
	for h := range doc {
		hooks = append(hooks, h)
	}
	sort.Strings(hooks)
	var out []command
	for _, h := range hooks {
		names := make([]string, 0, len(doc[h].Commands))
		for n := range doc[h].Commands {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if run := strings.TrimSpace(doc[h].Commands[n].Run); run != "" {
				out = append(out, command{name: h + " " + n, text: run, line: lineOf(data, run)})
			}
		}
		for i, j := range doc[h].Jobs {
			if run := strings.TrimSpace(j.Run); run != "" {
				name := j.Name
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
	type entry struct {
		Command   string   `json:"command"`
		Args      []string `json:"args"`
		URL       string   `json:"url"`
		ServerURL string   `json:"serverUrl"`
		HTTPURL   string   `json:"httpUrl"`
	}
	var doc struct {
		MCPServers map[string]entry `json:"mcpServers"`
		Servers    map[string]entry `json:"servers"`
	}
	if err := decodeJSONC(data, &doc); err != nil {
		return nil, err
	}
	all := map[string]entry{}
	for n, e := range doc.Servers {
		all[n] = e
	}
	for n, e := range doc.MCPServers {
		all[n] = e
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []server
	for _, n := range names {
		e := all[n]
		url := e.URL
		for _, u := range []string{e.ServerURL, e.HTTPURL} {
			if url == "" {
				url = u
			}
		}
		cmd := strings.TrimSpace(strings.Join(append([]string{e.Command}, e.Args...), " "))
		out = append(out, server{name: n, command: cmd, url: url, line: lineOf(data, n)})
	}
	return out, nil
}

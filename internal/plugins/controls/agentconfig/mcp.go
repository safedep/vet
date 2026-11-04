package agentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
)

// mcpServers reads the servers of an MCP config file. A file can hold one
// name in more than one section, and an agent can read either, so vet reads
// each entry of each section. A merge would let a harmless entry hide a
// malicious entry of the same name.
func mcpServers(data []byte, l agentfiles.MCPLayout) ([]server, error) {
	switch l.Format {
	case agentfiles.TOML:
		return tomlServers(data, l)
	case agentfiles.YAML:
		return yamlServers(data, l)
	}
	// Plain JSON is the common case, and stripJSONC would change nothing in
	// it, so vet strips the comments only when the plain read fails. A large
	// ~/.claude.json then costs one pass.
	if out, err := jsonServers(data, l); err == nil {
		return out, nil
	}
	return jsonServers(stripJSONC(data), l)
}

// serverOf reads one server entry. It reads the command and URL keys of
// every agent with an exact key match, so a key that one agent ignores does
// not hide a command that another agent runs.
func serverOf(name string, v any, line int, skip map[string]bool) (server, bool) {
	e := objectOf(v)
	if e == nil || skip[stringOf(e["type"])] {
		return server{}, false
	}
	url := ""
	for _, k := range []string{"url", "serverUrl", "httpUrl", "uri"} {
		if url == "" {
			url = stringOf(e[k])
		}
	}
	words := append(commandWords(e["command"]), stringOf(e["cmd"]))
	for _, a := range listOf(e["args"]) {
		words = append(words, stringOf(a))
	}
	// The words keep their own white space, so a run of spaces that pads
	// a payload past the edge of the screen still reaches the check.
	var parts []string
	for _, w := range words {
		if w != "" {
			parts = append(parts, w)
		}
	}
	// An old Zed command object holds its own env.
	env := envValues(e)
	env = append(env, envValues(objectOf(e["command"]))...)
	return server{name: name, command: strings.Join(parts, " "), url: url, line: line, env: env}, true
}

// envValues returns the values of the environment of a server.
func envValues(e object) []string {
	var out []string
	for _, k := range []string{"env", "envs", "environment"} {
		o := objectOf(e[k])
		for _, n := range sortedKeys(o) {
			if v := stringOf(o[n]); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// commandWords reads a server command: a string, a list of the executable
// and its arguments (OpenCode), or an object with a path and arguments (old
// Zed releases).
func commandWords(v any) []string {
	switch c := v.(type) {
	case string:
		return []string{c}
	case []any:
		out := make([]string, 0, len(c))
		for _, w := range c {
			out = append(out, stringOf(w))
		}
		return out
	}
	o := objectOf(v)
	if o == nil {
		return nil
	}
	out := []string{stringOf(o["path"])}
	for _, a := range listOf(o["args"]) {
		out = append(out, stringOf(a))
	}
	return out
}

// listName names a server of a list by its name key, or by its position. A
// server with no name gets a new name, and its finding a new id, when a
// server goes in before it.
func listName(v any, i int) string {
	if n := stringOf(objectOf(v)["name"]); n != "" {
		return n
	}
	return fmt.Sprintf("server %d", i+1)
}

// jsonWalk reads the servers of a JSON file in one pass. It decodes only the
// server entries and skips every other value, so a large file such as
// ~/.claude.json costs one read, and the line of each server comes from the
// same pass.
type jsonWalk struct {
	dec   *json.Decoder
	clean []byte
	skip  map[string]bool
	out   []server
	// off and line are the last offset that lineAt counted to, and its line.
	off  int64
	line int
}

func jsonServers(clean []byte, l agentfiles.MCPLayout) ([]server, error) {
	if len(bytes.TrimSpace(clean)) == 0 {
		return nil, nil
	}
	w := &jsonWalk{dec: json.NewDecoder(bytes.NewReader(clean)), clean: clean, skip: l.Skip, line: 1}
	err := w.root(l.Sections)
	// A second value after the root is an error, as in encoding/json. The
	// check reads the rest of the bytes, because the decoder would copy a
	// long run of white space into its buffer.
	if err != nil {
		return nil, w.syntaxError(err)
	}
	rest := clean[min(w.dec.InputOffset(), int64(len(clean))):]
	trimmed := bytes.TrimLeft(rest, " \t\r\n")
	if len(trimmed) == 0 {
		return w.out, nil
	}
	off := len(clean) - len(trimmed)
	return nil, &parseError{line: bytes.Count(clean[:off], []byte("\n")) + 1, err: errors.New("invalid data after the top-level value")}
}

func (w *jsonWalk) root(sections [][]string) error {
	t, err := w.dec.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		return w.object(sections)
	case json.Delim('['):
		return skipRest(w.dec)
	}
	return nil
}

// object reads the rest of an object. paths are the section paths relative
// to it.
func (w *jsonWalk) object(paths [][]string) error {
	for w.dec.More() {
		t, err := w.dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		section := false
		var deeper [][]string
		for _, p := range paths {
			if p[0] != key && p[0] != "*" {
				continue
			}
			if len(p) == 1 {
				section = true
			} else {
				deeper = append(deeper, p[1:])
			}
		}
		switch {
		case section:
			err = w.section()
		case len(deeper) > 0:
			err = w.nested(deeper)
		default:
			err = skipValue(w.dec)
		}
		if err != nil {
			return err
		}
	}
	_, err := w.dec.Token()
	return err
}

func (w *jsonWalk) nested(paths [][]string) error {
	t, err := w.dec.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		return w.object(paths)
	case json.Delim('['):
		return skipRest(w.dec)
	}
	return nil
}

// section reads the servers of a section: an object of names, or a list of
// servers with a name key.
func (w *jsonWalk) section() error {
	t, err := w.dec.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		for w.dec.More() {
			t, err := w.dec.Token()
			if err != nil {
				return err
			}
			name, _ := t.(string)
			line := w.lineAt(w.dec.InputOffset())
			if err := w.entry(name, line, -1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for i := 0; w.dec.More(); i++ {
			if err := w.entry("", w.lineAt(w.valueStart()), i); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = w.dec.Token()
	return err
}

// entry decodes one server. A list server (i >= 0) takes its name from the
// entry.
func (w *jsonWalk) entry(name string, line, i int) error {
	var v any
	if err := w.dec.Decode(&v); err != nil {
		return err
	}
	if i >= 0 {
		if objectOf(v) == nil {
			return nil
		}
		name = listName(v, i)
	}
	// One server past the limit is enough for Evaluate to report it. The
	// walk still reads the rest, so a syntax error later in the file shows.
	if len(w.out) > maxCommands {
		return nil
	}
	if s, ok := serverOf(name, v, line, w.skip); ok {
		w.out = append(w.out, s)
	}
	return nil
}

// valueStart returns the offset of the next value, past the white space and
// the comma that the decoder has not read yet.
func (w *jsonWalk) valueStart() int64 {
	off := w.dec.InputOffset()
	for off < int64(len(w.clean)) && strings.IndexByte(" \t\r\n,", w.clean[off]) >= 0 {
		off++
	}
	return off
}

// lineAt returns the line of offset off. The walk reads forward, so each call
// counts only the new bytes.
func (w *jsonWalk) lineAt(off int64) int {
	off = min(off, int64(len(w.clean)))
	if off > w.off {
		w.line += bytes.Count(w.clean[w.off:off], []byte("\n"))
		w.off = off
	}
	return w.line
}

func (w *jsonWalk) syntaxError(err error) error {
	off := w.dec.InputOffset()
	var se *json.SyntaxError
	switch {
	case errors.As(err, &se):
		off = se.Offset
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		err = io.ErrUnexpectedEOF
		off = int64(len(w.clean))
	}
	off = max(0, min(off, int64(len(w.clean))))
	return &parseError{line: bytes.Count(w.clean[:off], []byte("\n")) + 1, err: err}
}

// treeServers reads the servers at the sections of a decoded YAML or TOML
// file. line returns the line of the server at keys, or of the list server i
// in the section at keys, or 0.
func treeServers(doc any, l agentfiles.MCPLayout, data []byte, line func(keys []string, i int) int) []server {
	var out []server
	add := func(name string, v any, ln int) {
		if ln == 0 {
			ln = lineOf(data, name)
		}
		if s, ok := serverOf(name, v, ln, l.Skip); ok && len(out) <= maxCommands {
			out = append(out, s)
		}
	}
	var walk func(v any, keys, rest []string)
	walk = func(v any, keys, rest []string) {
		if len(rest) == 0 {
			if list := listOf(v); list != nil {
				for i, e := range list {
					if objectOf(e) != nil {
						add(listName(e, i), e, line(keys, i))
					}
				}
				return
			}
			o := objectOf(v)
			for _, n := range sortedKeys(o) {
				add(n, o[n], line(append(keys[:len(keys):len(keys)], n), -1))
			}
			return
		}
		o := objectOf(v)
		for _, k := range sortedKeys(o) {
			if rest[0] == "*" || rest[0] == k {
				walk(o[k], append(keys[:len(keys):len(keys)], k), rest[1:])
			}
		}
	}
	for _, sec := range l.Sections {
		walk(doc, nil, sec)
	}
	return out
}

// yamlServers reads a YAML file once into a node tree. The values come from
// the tree with the anchors and merge keys resolved, as the agent reads
// them. The lines come from the nodes.
func yamlServers(data []byte, l agentfiles.MCPLayout) ([]server, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, yamlError(err)
	}
	if root.Kind == 0 {
		return nil, nil
	}
	var doc any
	if err := root.Decode(&doc); err != nil {
		return nil, yamlError(err)
	}
	return treeServers(doc, l, data, func(keys []string, i int) int { return yamlNodeLine(&root, keys, i) }), nil
}

// yamlNodeLine returns the line of the key at keys, or of item i of the list
// at keys, or 0. It follows aliases and merge keys.
func yamlNodeLine(n *yaml.Node, keys []string, i int) int {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	line := 0
	for _, k := range keys {
		var key *yaml.Node
		key, n = yamlKey(n, k)
		if n == nil {
			return 0
		}
		line = key.Line
	}
	if i < 0 {
		return line
	}
	n = yamlDeref(n)
	if n.Kind != yaml.SequenceNode || i >= len(n.Content) {
		return 0
	}
	return yamlDeref(n.Content[i]).Line
}

// yamlKey returns the key and the value of k in the mapping n. A key of the
// mapping wins over a key that a merge key brings in, as in YAML.
func yamlKey(n *yaml.Node, k string) (key, val *yaml.Node) {
	n = yamlDeref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	var merges []*yaml.Node
	for j := 0; j+1 < len(n.Content); j += 2 {
		switch n.Content[j].Value {
		case k:
			return n.Content[j], n.Content[j+1]
		case "<<":
			merges = append(merges, n.Content[j+1])
		}
	}
	for _, m := range merges {
		m = yamlDeref(m)
		sources := []*yaml.Node{m}
		if m.Kind == yaml.SequenceNode {
			sources = m.Content
		}
		for _, src := range sources {
			if key, val := yamlKey(src, k); key != nil {
				return key, val
			}
		}
	}
	return nil, nil
}

func yamlDeref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// maxTOMLDots is the most dots that vet lets BurntSushi/toml parse. The
// parser costs time in the square of the parts of a dotted key, and a key
// of 40 000 parts takes seconds. The count takes each dot, also in a
// string, so a quote cannot hide one. A real config holds a few hundred.
const maxTOMLDots = 8 << 10

// tomlServers reads a TOML file. BurntSushi/toml gives no key positions, so
// the lines come from a scan of the key paths of each line.
func tomlServers(data []byte, l agentfiles.MCPLayout) ([]server, error) {
	if bytes.Count(data, []byte(".")) > maxTOMLDots {
		return nil, &parseError{line: 1, err: fmt.Errorf("the file holds more than %d dots, the most that vet parses", maxTOMLDots)}
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		line := 1
		var pe toml.ParseError
		if errors.As(err, &pe) && pe.Position.Line > 0 {
			line = pe.Position.Line
		}
		return nil, &parseError{line: line, err: err}
	}
	depth := 0
	for _, sec := range l.Sections {
		depth = max(depth, len(sec)+1)
	}
	lines := tomlLines(data, depth)
	return treeServers(doc, l, data, func(keys []string, _ int) int { return lines[strings.Join(keys, "\x00")] }), nil
}

// tomlLines maps each key path of up to depth parts to the first line that
// names it: a table header such as [mcp_servers."a.b"], or a dotted key such
// as mcp_servers.a.command = "x". A key in an inline table gets no line, and
// the server falls back to the line of its name. The depth bounds the work
// of a key with many parts. A line in a multi-line string is not a key.
func tomlLines(data []byte, depth int) map[string]int {
	out := map[string]int{}
	record := func(keys []string, line int) {
		k := ""
		for i := range min(len(keys), depth) {
			if i > 0 {
				k += "\x00"
			}
			k += keys[i]
			if _, ok := out[k]; !ok {
				out[k] = line
			}
		}
	}
	var table []string
	multi := ""
	for i, raw := range strings.Split(string(data), "\n") {
		if multi != "" {
			if strings.Contains(raw, multi) {
				multi = ""
			}
			continue
		}
		for _, q := range []string{`"""`, `'''`} {
			if strings.Count(raw, q)%2 == 1 {
				multi = q
			}
		}
		s := strings.TrimSpace(raw)
		switch {
		case s == "" || s[0] == '#':
			continue
		case strings.HasPrefix(s, "[["):
			if end := strings.Index(s, "]]"); end > 0 {
				table = tomlKeys(s[2:end])
				record(table, i+1)
			}
		case s[0] == '[':
			if end := tomlKeyEnd(s[1:], ']'); end >= 0 {
				table = tomlKeys(s[1 : end+1])
				record(table, i+1)
			}
		default:
			if eq := tomlKeyEnd(s, '='); eq > 0 {
				record(append(table[:len(table):len(table)], tomlKeys(s[:eq])...), i+1)
			}
		}
	}
	return out
}

// tomlKeyEnd returns the index of the first stop outside a quoted key, or
// -1.
func tomlKeyEnd(s string, stop byte) int {
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == stop:
			return i
		}
	}
	return -1
}

// tomlKeys splits a dotted TOML key into its parts, with the quotes removed.
func tomlKeys(s string) []string {
	var out []string
	for {
		end := tomlKeyEnd(s, '.')
		part := s
		if end >= 0 {
			part = s[:end]
		}
		out = append(out, tomlKeyPart(strings.TrimSpace(part)))
		if end < 0 {
			return out
		}
		s = s[end+1:]
	}
}

func tomlKeyPart(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
	}
	return s
}

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safedep/dry/usefulerror"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/config/appdir"
)

// CodeKeyNotSet is the error code of a delete of a key that the file does
// not set. The command exits with code 2.
const CodeKeyNotSet = "config_key_not_set"

// Values returns each leaf key of a config with its value, the plugin keys
// included.
func Values(c *Config) (map[string]any, error) {
	tree, err := toTree(*c)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	flatten(tree, "", out)
	for _, k := range Keys() {
		if _, ok := out[k]; !ok {
			out[k] = nil
		}
	}
	return out, nil
}

func flatten(tree map[string]any, prefix string, out map[string]any) {
	for k, v := range tree {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok && (len(sub) > 0 || key == "plugins") {
			flatten(sub, key, out)
			continue
		}
		out[key] = v
	}
}

// Get returns the value of one key. An unknown key is an error that
// suggests the closest key.
func Get(c *Config, key string) (any, error) {
	if !IsKnownKey(key) {
		return nil, unknownKey(key)
	}
	vals, err := Values(c)
	if err != nil {
		return nil, err
	}
	return vals[key], nil
}

// SetInFile sets a key in a config file. It edits the YAML node tree, so
// the comments and the key order of the file stay. It checks the key, the
// value and the whole file before it writes, and writes through a
// temporary file and a rename.
func SetInFile(path, key, raw string) error {
	if !IsKnownKey(key) {
		return unknownKey(key)
	}
	v, err := parseValue(key, raw)
	if err != nil {
		return newError(CodeInvalid, fmt.Sprintf("%s %v, got %q", key, err, raw),
			"vet did not write the value to "+path)
	}
	doc, err := readDoc(path)
	if err != nil {
		return err
	}
	var node yaml.Node
	if err := node.Encode(v); err != nil {
		return err
	}
	setNode(root(doc), strings.Split(key, "."), &node)
	return writeDoc(path, doc)
}

// DeleteInFile removes a key from a config file and the sections that it
// leaves empty.
func DeleteInFile(path, key string) error {
	doc, err := readDoc(path)
	if err != nil {
		return err
	}
	if !deleteNode(root(doc), strings.Split(key, ".")) {
		if !IsKnownKey(key) {
			return unknownKey(key)
		}
		return newError(CodeKeyNotSet, fmt.Sprintf("%s: %s does not set the key", key, path), "vet config show --origin shows where each value comes from.")
	}
	return writeDoc(path, doc)
}

func readDoc(path string) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && len(bytes.TrimSpace(b)) == 0) {
		return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}, nil
	}
	if err != nil {
		return nil, newError(CodeFileUnreadable, fmt.Sprintf("read config file %s: %v", path, err), "Check the file mode.")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, newError(CodeFileInvalid, fmt.Sprintf("%s: %v", path, err), "Fix the YAML, or run vet config edit.")
	}
	if len(doc.Content) == 0 {
		// yaml.v3 drops the comments of a file that has only comments.
		comments := string(bytes.TrimSpace(b))
		return &yaml.Node{Kind: yaml.DocumentNode, HeadComment: comments, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}, nil
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return nil, newError(CodeFileInvalid, fmt.Sprintf("%s is not a YAML mapping", path), "Fix the YAML, or run vet config edit.")
	}
	return &doc, nil
}

func root(doc *yaml.Node) *yaml.Node { return doc.Content[0] }

func setNode(m *yaml.Node, path []string, value *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != path[0] {
			continue
		}
		if len(path) == 1 {
			old := m.Content[i+1]
			value.HeadComment, value.LineComment, value.FootComment = old.HeadComment, old.LineComment, old.FootComment
			m.Content[i+1] = value
			return
		}
		if m.Content[i+1].Kind != yaml.MappingNode {
			m.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode}
		}
		setNode(m.Content[i+1], path[1:], value)
		return
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Value: path[0]}
	if len(path) == 1 {
		m.Content = append(m.Content, key, value)
		return
	}
	sub := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, key, sub)
	setNode(sub, path[1:], value)
}

func deleteNode(m *yaml.Node, path []string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != path[0] {
			continue
		}
		if len(path) == 1 {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
		sub := m.Content[i+1]
		if sub.Kind != yaml.MappingNode || !deleteNode(sub, path[1:]) {
			return false
		}
		if len(sub.Content) == 0 {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
		}
		return true
	}
	return false
}

// writeDoc checks the new file with Load and Validate, then writes it with
// mode 0600.
func writeDoc(path string, doc *yaml.Node) (err error) {
	b, err := encodeDoc(doc)
	if err != nil {
		return err
	}
	if err := appdir.Ensure(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rmErr := os.Remove(tmp.Name()); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				err = errors.Join(err, rmErr)
			}
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	l, err := Load(LoadOptions{ConfigFile: tmp.Name(), LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		return rejected(err, tmp.Name(), path)
	}
	if err := l.Validate(); err != nil {
		return rejected(err, tmp.Name(), path)
	}
	return os.Rename(tmp.Name(), path)
}

// rejected names the config file in place of its temporary copy, and says
// that the file did not change.
func rejected(err error, tmp, path string) error {
	ue, ok := usefulerror.AsUsefulError(err)
	if !ok {
		return err
	}
	return newError(ue.Code(), strings.ReplaceAll(ue.HumanError(), tmp, path), "vet did not write the change to "+path)
}

// encodeDoc returns the YAML of a config file. yaml.v3 writes an empty
// mapping as "{}", which is JSON, so a file with no key keeps only its
// comments.
func encodeDoc(doc *yaml.Node) ([]byte, error) {
	if m := root(doc); len(m.Content) == 0 {
		var comments []string
		for _, c := range []string{doc.HeadComment, m.HeadComment, m.LineComment, m.FootComment, doc.FootComment} {
			if c != "" {
				comments = append(comments, c+"\n")
			}
		}
		return []byte(strings.Join(comments, "")), nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SortedKeys returns the keys of a value map, sorted.
func SortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

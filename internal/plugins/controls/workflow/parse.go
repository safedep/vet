package workflow

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"
)

// document is a parsed workflow or composite action file.
type document struct {
	root  *yaml.Node
	lines []string
}

// step is one step of a job, or of a composite action. job is "" in a
// composite action.
type step struct {
	job  string
	node *yaml.Node
}

// usesRef is a uses: value of a step or of a job that calls a reusable
// workflow.
type usesRef struct {
	job  string
	node *yaml.Node
}

// parse returns nil for a file that is not a YAML mapping, such as a
// template. The extractor accepts such a file too.
func parse(data []byte) *document {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	root := resolve(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return nil
	}
	return &document{root: root, lines: strings.Split(string(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))), "\n")}
}

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// get returns the value of a key of a mapping, or nil.
func get(m *yaml.Node, key string) *yaml.Node {
	m = resolve(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return resolve(m.Content[i+1])
		}
	}
	return nil
}

// scalar returns the value of a scalar node, or "".
func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// triggers returns the event names of the on: key.
func (d *document) triggers() []string {
	on := get(d.root, "on")
	if on == nil {
		return nil
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return []string{on.Value}
	case yaml.SequenceNode:
		var out []string
		for _, n := range on.Content {
			out = append(out, scalar(resolve(n)))
		}
		return out
	case yaml.MappingNode:
		var out []string
		for i := 0; i < len(on.Content); i += 2 {
			out = append(out, on.Content[i].Value)
		}
		return out
	}
	return nil
}

// jobs returns the job ids and nodes, in file order.
func (d *document) jobs() []step {
	jobs := get(d.root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}
	var out []step
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		out = append(out, step{job: jobs.Content[i].Value, node: resolve(jobs.Content[i+1])})
	}
	return out
}

// steps returns the steps of every job, or of a composite action, in file
// order.
func (d *document) steps() []step {
	var out []step
	add := func(job string, steps *yaml.Node) {
		if steps == nil || steps.Kind != yaml.SequenceNode {
			return
		}
		for _, s := range steps.Content {
			if s = resolve(s); s.Kind == yaml.MappingNode {
				out = append(out, step{job: job, node: s})
			}
		}
	}
	if runs := get(d.root, "runs"); runs != nil {
		add("", get(runs, "steps"))
		return out
	}
	for _, j := range d.jobs() {
		add(j.job, get(j.node, "steps"))
	}
	return out
}

// uses returns every uses: of the steps and of the jobs that call a
// reusable workflow.
func (d *document) uses() []usesRef {
	var out []usesRef
	for _, j := range d.jobs() {
		if u := get(j.node, "uses"); scalar(u) != "" {
			out = append(out, usesRef{job: j.job, node: u})
		}
	}
	for _, s := range d.steps() {
		if u := get(s.node, "uses"); scalar(u) != "" {
			out = append(out, usesRef{job: s.job, node: u})
		}
	}
	return out
}

// line returns the source line of an offset in a scalar value. A block
// scalar starts on the line after its indicator. The line of a folded
// scalar is approximate.
func line(n *yaml.Node, offset int) int {
	l := n.Line + strings.Count(n.Value[:offset], "\n")
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		l++
	}
	return l
}

// text returns the trimmed source line, or "".
func (d *document) text(l int) string {
	if l < 1 || l > len(d.lines) {
		return ""
	}
	return strings.TrimSpace(d.lines[l-1])
}

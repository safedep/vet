// Package fix holds the explicit fixes. A scan never writes the scanned
// repository (decisions D10). A fix runs only when the user runs its
// command.
package fix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/github"
)

// Resolver resolves a tag or a branch of a GitHub repository to a commit
// SHA.
type Resolver interface {
	ResolveSHA(ctx context.Context, owner, repo, ref string) (string, error)
}

// Edit is one uses: value that the fix pins.
type Edit struct {
	Line   int    `json:"line"`
	Action string `json:"action"`
	Ref    string `json:"ref"`
	SHA    string `json:"sha"`
	Old    string `json:"old"`
	New    string `json:"new"`
}

// File is the plan for one workflow or action file.
type File struct {
	Path   string `json:"path"`
	Edits  []Edit `json:"edits"`
	before []byte
	after  []byte
}

// Failure is an action that the fix could not pin.
type Failure struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Action string `json:"action"`
	Error  string `json:"error"`
	// Reason is a short form of Error for a person.
	Reason string `json:"-"`
	// NeedsToken is true when a GitHub token can fix the failure.
	NeedsToken bool `json:"-"`
}

// Plan is the set of edits of a run.
type Plan struct {
	Root     string    `json:"root"`
	Files    []*File   `json:"files"`
	Failures []Failure `json:"failures"`
}

// NeedsToken is true when a GitHub token can fix a failure of the plan.
func (p *Plan) NeedsToken() bool {
	for _, f := range p.Failures {
		if f.NeedsToken {
			return true
		}
	}
	return false
}

// PinOptions configure PlanPins.
type PinOptions struct {
	Root     string
	Resolver Resolver
	// SameRepo is owner/repo of the repository at Root. Its actions stay.
	// Empty reads the origin remote of the git repository.
	SameRepo string
}

// PlanPins finds each third-party uses: with a tag or a branch in the
// workflows and the composite actions under Root, and resolves it to a
// commit SHA. Local actions, Docker images, actions of the same repository
// and expressions stay as they are.
func PlanPins(ctx context.Context, o PinOptions) (*Plan, error) {
	if o.SameRepo == "" {
		o.SameRepo = github.OriginRepo(o.Root)
	}
	files, err := workflowFiles(o.Root)
	if err != nil {
		return nil, err
	}
	cache := map[string]string{}
	return plan(ctx, o.Root, files, func(ctx context.Context, repo, ref string) (Pin, bool, error) {
		if github.IsCommitSHA(ref) || strings.EqualFold(repo, o.SameRepo) {
			return Pin{}, false, nil
		}
		key := repo + "@" + ref
		sha, ok := cache[key]
		if !ok {
			owner, name, _ := strings.Cut(repo, "/")
			var err error
			if sha, err = o.Resolver.ResolveSHA(ctx, owner, name, ref); err != nil {
				return Pin{}, false, err
			}
			cache[key] = sha
		}
		return Pin{SHA: sha, Ref: ref, KeepComment: true}, true, nil
	})
}

// Pin is the commit SHA of an action and the ref that the comment of the
// uses: line names.
type Pin struct {
	SHA string
	Ref string
	// KeepComment keeps the old comment of the line after the ref.
	KeepComment bool
}

// RepinOptions configure PlanRepins.
type RepinOptions struct {
	Root string
	// Files are the slash paths under Root that the plan edits.
	Files []string
	// Pins maps owner/repo to the new pin of its actions.
	Pins map[string]Pin
}

// PlanRepins moves each action of Pins in Files to its new pin. A line
// that has the pin already stays.
func PlanRepins(ctx context.Context, o RepinOptions) (*Plan, error) {
	return plan(ctx, o.Root, o.Files, func(_ context.Context, repo, ref string) (Pin, bool, error) {
		p, ok := o.Pins[strings.ToLower(repo)]
		return p, ok && !strings.EqualFold(ref, p.SHA), nil
	})
}

// PinnedTags returns the tag in the comment of each action that a commit
// SHA pins, by owner/repo in lower case. It fails when data is not YAML.
func PinnedTags(data []byte) (map[string]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range usesNodes(&doc) {
		action, ref, ok := strings.Cut(n.Value, "@")
		parts := strings.SplitN(action, "/", 3)
		if !ok || len(parts) < 2 || !github.IsCommitSHA(ref) {
			continue
		}
		comment := strings.Fields(strings.TrimPrefix(n.LineComment, "#"))
		if len(comment) == 0 {
			continue
		}
		out[strings.ToLower(parts[0]+"/"+parts[1])] = strings.TrimSuffix(comment[0], ";")
	}
	return out, nil
}

// pinner returns the pin of an action of repo at ref, or false to keep the
// line.
type pinner func(ctx context.Context, repo, ref string) (Pin, bool, error)

func plan(ctx context.Context, root string, files []string, pin pinner) (*Plan, error) {
	p := &Plan{Root: root, Files: []*File{}, Failures: []Failure{}}
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		f, fails := planFile(ctx, rel, data, pin)
		p.Failures = append(p.Failures, fails...)
		if len(f.Edits) > 0 {
			p.Files = append(p.Files, f)
		}
	}
	return p, nil
}

func planFile(ctx context.Context, rel string, data []byte, pin pinner) (*File, []Failure) {
	f := &File{Path: rel, Edits: []Edit{}, before: data}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return f, nil
	}
	lines := strings.SplitAfter(string(data), "\n")
	var fails []Failure
	for _, n := range usesNodes(&doc) {
		action, ref, ok := strings.Cut(n.Value, "@")
		if !ok || !pinnable(n.Value) {
			continue
		}
		parts := strings.SplitN(action, "/", 3)
		if len(parts) < 2 {
			continue
		}
		p, ok, err := pin(ctx, parts[0]+"/"+parts[1], ref)
		if err != nil {
			reason, token := github.Reason(err)
			fails = append(fails, Failure{Path: rel, Line: n.Line, Action: n.Value, Error: err.Error(), Reason: reason, NeedsToken: token})
			continue
		}
		if !ok {
			continue
		}
		old, updated, ok := rewriteLine(lines[n.Line-1], n, action+"@"+p.SHA, p.Ref, p.KeepComment)
		if !ok {
			const msg = "the uses: value is not on one line"
			fails = append(fails, Failure{Path: rel, Line: n.Line, Action: n.Value, Error: msg, Reason: msg})
			continue
		}
		lines[n.Line-1] = updated
		f.Edits = append(f.Edits, Edit{Line: n.Line, Action: action, Ref: p.Ref, SHA: p.SHA, Old: strings.TrimRight(old, "\r\n"), New: strings.TrimRight(updated, "\r\n")})
	}
	f.after = []byte(strings.Join(lines, ""))
	return f, fails
}

func pinnable(v string) bool {
	return !strings.HasPrefix(v, "./") && !strings.HasPrefix(v, "docker://") && !strings.Contains(v, "${{")
}

// rewriteLine replaces the uses: value at its column, keeps its quotes, and
// writes ref as the comment. keep puts ref before an existing comment, and
// otherwise ref replaces it.
func rewriteLine(line string, n *yaml.Node, value, ref string, keep bool) (string, string, bool) {
	start := n.Column - 1
	if start < 0 || start >= len(line) {
		return line, line, false
	}
	quote := ""
	if q := line[start]; q == '"' || q == '\'' {
		quote = string(q)
	}
	raw := quote + n.Value + quote
	if !strings.HasPrefix(line[start:], raw) {
		return line, line, false
	}
	rest := line[start+len(raw):]
	eol := ""
	if trimmed := strings.TrimRight(rest, "\r\n"); len(trimmed) != len(rest) {
		eol = rest[len(trimmed):]
		rest = trimmed
	}
	comment := " # " + ref
	if i := strings.Index(rest, "#"); i >= 0 {
		if keep {
			comment = " # " + ref + "; " + strings.TrimSpace(rest[i+1:])
		}
		rest = rest[:i]
	}
	updated := line[:start] + quote + value + quote + strings.TrimRight(rest, " \t") + comment + eol
	return line, updated, true
}

// usesNodes returns the value node of each uses: key, in file order.
func usesNodes(n *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.Value == "uses" && v.Kind == yaml.ScalarNode {
					out = append(out, v)
					continue
				}
				walk(v)
			}
		}
	}
	walk(n)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// workflowFiles lists the workflows and the composite actions under root.
func workflowFiles(root string) ([]string, error) {
	var out []string
	fsys := os.DirFS(root)
	for _, dir := range []string{".github/workflows", ".github/actions"} {
		err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				return fs.SkipDir
			}
			if err != nil {
				return err
			}
			ext := path.Ext(p)
			if d.IsDir() || (ext != ".yml" && ext != ".yaml") {
				return nil
			}
			if dir == ".github/workflows" && path.Dir(p) != dir {
				return nil
			}
			if dir == ".github/actions" && !strings.HasPrefix(path.Base(p), "action.") {
				return nil
			}
			out = append(out, p)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Diff returns a unified diff of the plan, one hunk for each edit.
func (p *Plan) Diff() string {
	var b strings.Builder
	for _, f := range p.Files {
		fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", f.Path, f.Path)
		for _, e := range f.Edits {
			fmt.Fprintf(&b, "@@ -%d +%d @@\n-%s\n+%s\n", e.Line, e.Line, e.Old, e.New)
		}
	}
	return b.String()
}

// Apply writes each changed file through a temporary file and a rename, so
// a failed write leaves the old file. It keeps the file mode.
func (p *Plan) Apply() error {
	for _, f := range p.Files {
		if bytes.Equal(f.before, f.after) {
			continue
		}
		if err := writeAtomic(filepath.Join(p.Root, filepath.FromSlash(f.Path)), f.after); err != nil {
			return err
		}
	}
	return nil
}

// Edits returns the number of edits.
func (p *Plan) Edits() int {
	n := 0
	for _, f := range p.Files {
		n += len(f.Edits)
	}
	return n
}

func writeAtomic(dst string, data []byte) (err error) {
	info, err := os.Stat(dst)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
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
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

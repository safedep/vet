// Package actionslock reads the GitHub Actions lockfile,
// .github/workflows/actions.lock, with the parser of GitHub. GitHub runs
// each step action of a workflow that the file lists at the commit that the
// file records, and fails the run when a step action has no entry.
//
// GitHub checks that the recorded commit is reachable from the recorded
// ref, not that it is the commit of the ref. A lockfile change can move the
// commit of a tag to another commit of its history. vet does not detect
// this.
package actionslock

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/github/actions-lockfile/go/pkg/lockfile"
	"gopkg.in/yaml.v3"
)

const (
	name         = "actions.lock"
	workflowsDir = ".github/workflows"
	// maxKeys is the most keys that vet reads in one YAML mapping. The YAML
	// library finds duplicate keys in quadratic time, so a file of 1 MiB of
	// keys costs minutes. A real lockfile has far fewer.
	maxKeys = 10000
)

// MaxSize is the largest lockfile that vet reads, in bytes.
const MaxSize = lockfile.MaxParseSize

// policy accepts only the schema version that GitHub writes since general
// availability. vet does not trust a file that it cannot read as GitHub
// does.
var policy = lockfile.VersionPolicy{Min: "v0.0.3", Max: "v0.0.3"}

// Lock is a parsed lockfile. A nil Lock locks nothing.
type Lock struct {
	f lockfile.File
}

// Parse parses the content of a lockfile.
func Parse(data []byte) (*Lock, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("the file has more than %d bytes", MaxSize)
	}
	if err := checkKeys(data); err != nil {
		return nil, err
	}
	f, err := lockfile.ParseWithPolicy(data, policy)
	if err != nil {
		return nil, err
	}
	return &Lock{f: f}, nil
}

func checkKeys(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	var walk func(*yaml.Node) error
	walk = func(n *yaml.Node) error {
		if n.Kind == yaml.MappingNode && len(n.Content)/2 > maxKeys {
			return fmt.Errorf("line %d: a mapping has more than %d keys", n.Line, maxKeys)
		}
		for _, c := range n.Content {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&root)
}

// Read reads the lockfile of the repository at root in fsys. It returns
// nil and no error when the repository has no lockfile.
func Read(fsys fs.FS, root string) (*Lock, error) {
	var c Cache
	return c.Read(fsys, root)
}

// Cache parses each distinct lockfile once. A scan reads the lockfile of a
// repository for each of its workflows, and a hostile lockfile of 1 MiB
// costs time to parse. The zero value is ready to use.
type Cache struct {
	mu    sync.Mutex
	locks map[[sha256.Size]byte]parsed
}

type parsed struct {
	lock *Lock
	err  error
}

// Read is Read with the parse of each distinct content kept.
func (c *Cache) Read(fsys fs.FS, root string) (*Lock, error) {
	file, data, err := readFile(fsys, root)
	if err != nil || data == nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.locks[sum]
	if !ok {
		p.lock, p.err = Parse(data)
		if p.err != nil {
			p.err = fmt.Errorf("%s: %w", file, p.err)
		}
		if c.locks == nil {
			c.locks = map[[sha256.Size]byte]parsed{}
		}
		c.locks[sum] = p
	}
	return p.lock, p.err
}

// readFile returns the path and the content of the lockfile of the
// repository at root, or no content when there is no lockfile. GitHub reads
// the file from git, so a link, or a name in another case, is not the
// lockfile.
func readFile(fsys fs.FS, root string) (string, []byte, error) {
	dir := path.Join(root, workflowsDir)
	entries, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	i := slices.IndexFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name })
	if i < 0 || !entries[i].Type().IsRegular() {
		return "", nil, nil
	}
	file := path.Join(dir, name)
	info, err := entries[i].Info()
	if err != nil {
		return "", nil, err
	}
	if info.Size() > MaxSize {
		return "", nil, fmt.Errorf("%s: the file has more than %d bytes", file, MaxSize)
	}
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", nil, err
	}
	if data == nil {
		data = []byte{}
	}
	return file, data, nil
}

// LockfileRoot reports a repository path that is a lockfile, and returns
// the folder that holds its .github folder.
func LockfileRoot(p string) (string, bool) {
	if path.Base(p) != name {
		return "", false
	}
	return rootOf(p)
}

// WorkflowKey splits the path of a workflow file into the folder that
// holds its .github folder and the key of the workflow in the lockfile. ok
// is false for a file that is not directly in a .github/workflows folder,
// such as a composite action.
func WorkflowKey(p string) (root, key string, ok bool) {
	if path.Base(p) == name {
		return "", "", false
	}
	if root, ok = rootOf(p); !ok {
		return "", "", false
	}
	return root, strings.TrimPrefix(p, root+"/"), true
}

// rootOf returns the folder that holds the .github folder of a file
// directly in a .github/workflows folder.
func rootOf(p string) (string, bool) {
	dir := path.Dir(p)
	if dir == workflowsDir {
		return ".", true
	}
	if root, ok := strings.CutSuffix(dir, "/"+workflowsDir); ok {
		return root, true
	}
	return "", false
}

// ActionRoot splits the path of a composite action file into the folder
// that holds its .github folder and the folder of the action, relative to
// that folder. ok is false for a file that is not an action.yml or an
// action.yaml under a .github/actions folder.
func ActionRoot(p string) (root, dir string, ok bool) {
	if b := path.Base(p); b != "action.yml" && b != "action.yaml" {
		return "", "", false
	}
	q := "/" + p
	i := strings.Index(q, "/.github/actions/")
	if i < 0 {
		return "", "", false
	}
	root = "."
	if i > 0 {
		root = q[1:i]
	}
	return root, path.Dir(q[i+1:]), true
}

// IsAction reports a uses: value that names a repository action. A
// listed workflow must lock it. A reusable workflow, a Docker image and a
// local action need no lockfile entry.
func IsAction(uses string) bool {
	return lockfile.ParseActionRef(uses) != nil
}

// Status is what the lockfile says about the uses: value of a step.
type Status int

const (
	// Unlisted is a step of a workflow that the lockfile does not list, or
	// a uses: value that names no repository action, such as a Docker
	// image. GitHub runs it unlocked.
	Unlisted Status = iota
	// Locked is a step that GitHub runs at the recorded commit.
	Locked
	// Missing is a step of a listed workflow that has no entry. GitHub
	// fails the run.
	Missing
)

// WorkflowLock is the part of a lockfile for one workflow.
type WorkflowLock struct {
	listed bool
	keys   map[string]bool
}

// Workflow returns the part of the lockfile for the workflow key.
func (l *Lock) Workflow(key string) WorkflowLock {
	if l == nil {
		return WorkflowLock{}
	}
	_, listed := l.f.LookupWorkflow(key)
	return WorkflowLock{listed: listed, keys: l.locked(key)}
}

// Workflows returns the part of the lockfile that all the workflow keys
// share. A step of a local action runs under each workflow that uses the
// action, so the lockfile locks the step only when it locks it for each of
// them.
func (l *Lock) Workflows(keys []string) WorkflowLock {
	if l == nil || len(keys) == 0 {
		return WorkflowLock{}
	}
	out := l.Workflow(keys[0])
	for _, k := range keys[1:] {
		w := l.Workflow(k)
		out.listed = out.listed && w.listed
		for key := range out.keys {
			if !w.keys[key] {
				delete(out.keys, key)
			}
		}
	}
	return out
}

// Callers returns, for the folder of each local action, the keys of the
// listed workflows that use it, directly or through another local action.
// GitHub locks the remote actions of such an action under each of these
// workflows. The folders are relative to root. A file that vet cannot read
// uses no action.
func (l *Lock) Callers(fsys fs.FS, root string) map[string][]string {
	out := map[string][]string{}
	if l == nil {
		return out
	}
	for _, w := range slices.Sorted(maps.Keys(l.f.Workflows)) {
		seen := map[string]bool{}
		queue := localUses(fsys, path.Join(root, w))
		for len(queue) > 0 {
			d := queue[0]
			queue = queue[1:]
			if seen[d] {
				continue
			}
			seen[d] = true
			out[d] = append(out[d], w)
			for _, f := range []string{"action.yml", "action.yaml"} {
				queue = append(queue, localUses(fsys, path.Join(root, d, f))...)
			}
		}
	}
	return out
}

// localUses returns the folder of each local action, as ./path or $/path,
// that a workflow or action file uses.
func localUses(fsys fs.FS, file string) []string {
	info, err := fs.Stat(fsys, file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSize {
		return nil
	}
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		for i, c := range n.Content {
			if n.Kind == yaml.MappingNode && i%2 == 0 && c.Value == "uses" && i+1 < len(n.Content) {
				v, _, _ := strings.Cut(n.Content[i+1].Value, "@")
				for _, prefix := range []string{"./", "$/"} {
					if rest, ok := strings.CutPrefix(v, prefix); ok {
						if d := path.Clean(rest); fs.ValidPath(d) && d != "." {
							out = append(out, d)
						}
					}
				}
				continue
			}
			walk(c)
		}
	}
	walk(&doc)
	return out
}

// Listed reports whether the lockfile lists the workflow. GitHub enforces
// the lockfile only for a listed workflow.
func (w WorkflowLock) Listed() bool { return w.listed }

// Status returns what the lockfile says about the uses: value of a step.
func (w WorkflowLock) Status(uses string) Status {
	ref := lockfile.ParseActionRef(uses)
	switch {
	case !w.listed || ref == nil:
		return Unlisted
	case w.keys[lockfile.IndexKey(ref.Owner, ref.Repo, ref.Ref)]:
		return Locked
	}
	return Missing
}

// locked returns the keys, as owner/repo@ref, that the lockfile locks for
// the workflow. An entry of another host than GitHub.com does not count.
func (l *Lock) locked(workflow string) map[string]bool {
	out := map[string]bool{}
	keys, _ := l.f.LookupWorkflow(workflow)
	for _, k := range keys {
		if a, ok := l.f.Dependencies[k]; ok && (a.Hostname == "" || a.Hostname == "github.com") {
			out[k] = true
		}
	}
	return out
}

// Coverage maps each workflow key of a lockfile to the keys that the
// lockfile locks for it.
type Coverage map[string][]string

// Coverage returns the coverage of the lockfile.
func (l *Lock) Coverage() Coverage {
	out := Coverage{}
	if l == nil {
		return out
	}
	for w := range l.f.Workflows {
		if keys := l.locked(w); len(keys) > 0 {
			out[w] = slices.Sorted(maps.Keys(keys))
		}
	}
	return out
}

// Lost returns the workflow keys that lose a locked key from c to head.
func (c Coverage) Lost(head Coverage) []string {
	var out []string
	for w, keys := range c {
		if slices.ContainsFunc(keys, func(k string) bool { return !slices.Contains(head[w], k) }) {
			out = append(out, w)
		}
	}
	slices.Sort(out)
	return out
}

// Enforced reports whether GitHub enforces the lockfile for the GitHub API
// at apiURL. GitHub.com and GHE.com enforce it. GitHub Enterprise Server
// does not.
func Enforced(apiURL string) bool {
	if apiURL == "" {
		return true
	}
	u, err := url.Parse(apiURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "api.github.com" || strings.HasSuffix(host, ".ghe.com")
}

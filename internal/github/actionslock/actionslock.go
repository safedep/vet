// Package actionslock reads the GitHub Actions lockfile,
// .github/workflows/actions.lock. GitHub runs each step action of a
// workflow that the file lists at the commit that the file records, and
// fails the run when a step action has no entry.
//
// GitHub checks that the recorded commit is reachable from the recorded
// ref, not that it is the commit of the ref. A lockfile change can lock a
// tag to an older commit of its history. vet does not detect this.
package actionslock

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/github/actions-lockfile/go/pkg/lockfile"
)

// Name is the file name of the lockfile in the workflows folder.
const Name = "actions.lock"

// MaxSize is the largest lockfile that vet reads, in bytes.
const MaxSize = lockfile.MaxParseSize

const workflowsDir = ".github/workflows"

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
	f, err := lockfile.ParseWithPolicy(data, policy)
	if err != nil {
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Read reads the lockfile of the repository at root in fsys. It returns
// nil and no error when the repository has no lockfile. GitHub reads the
// file from git, so a link, or a name in another case, is not the
// lockfile.
func Read(fsys fs.FS, root string) (*Lock, error) {
	dir := path.Join(root, workflowsDir)
	entries, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(entries, func(e fs.DirEntry) bool { return e.Name() == Name })
	if i < 0 || !entries[i].Type().IsRegular() {
		return nil, nil
	}
	file := path.Join(dir, Name)
	info, err := entries[i].Info()
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxSize {
		return nil, fmt.Errorf("%s: the file has more than %d bytes", file, MaxSize)
	}
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return nil, err
	}
	l, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return l, nil
}

// Lockfile reports a repository path that is a lockfile, and returns the
// folder that holds its .github folder.
func Lockfile(p string) (root string, ok bool) {
	if path.Base(p) != Name {
		return "", false
	}
	return rootOf(p)
}

// Workflow splits the path of a workflow file into the folder that holds
// its .github folder and the key of the workflow in the lockfile. ok is
// false for a file that is not directly in a .github/workflows folder,
// such as a composite action.
func Workflow(p string) (root, key string, ok bool) {
	if path.Base(p) == Name {
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
	root, ok := strings.CutSuffix(dir, "/"+workflowsDir)
	return root, ok
}

// Lists reports whether the lockfile lists the workflow. GitHub enforces
// the lockfile only for a listed workflow.
func (l *Lock) Lists(workflow string) bool {
	if l == nil {
		return false
	}
	_, ok := l.f.LookupWorkflow(workflow)
	return ok
}

// ListsAny reports whether the lockfile lists a workflow. A composite
// action of the repository then runs under a locked workflow.
func (l *Lock) ListsAny() bool {
	return l != nil && len(l.f.Workflows) > 0
}

// Locks reports whether the lockfile locks the uses: value of a step of
// the workflow to a commit. A uses: value that names no repository action,
// such as a Docker image or a reusable workflow, is never locked.
func (l *Lock) Locks(workflow, uses string) bool {
	ref := lockfile.ParseActionRef(uses)
	if l == nil || ref == nil {
		return false
	}
	return l.Locked(workflow)[lockfile.IndexKey(ref.Owner, ref.Repo, ref.Ref)]
}

// IsAction reports a uses: value that names a repository action, which a
// listed workflow must lock.
func IsAction(uses string) bool {
	return lockfile.ParseActionRef(uses) != nil
}

// Locked returns the keys, as owner/repo@ref, that the lockfile locks for
// the workflow. An entry of another host than GitHub.com does not count.
func (l *Lock) Locked(workflow string) map[string]bool {
	out := map[string]bool{}
	if l == nil {
		return out
	}
	keys, _ := l.f.LookupWorkflow(workflow)
	for _, k := range keys {
		if a, ok := l.f.Dependencies[k]; ok && (a.Hostname == "" || a.Hostname == "github.com") {
			out[k] = true
		}
	}
	return out
}

// Coverage returns the keys that the lockfile locks for each workflow that
// it lists.
func (l *Lock) Coverage() map[string][]string {
	out := map[string][]string{}
	if l == nil {
		return out
	}
	for w := range l.f.Workflows {
		keys := slices.Sorted(maps.Keys(l.Locked(w)))
		if len(keys) > 0 {
			out[w] = keys
		}
	}
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

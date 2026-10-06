package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/gitbase"
	"github.com/safedep/vet/v2/internal/plugins/policysources/file"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/plugin"
)

// policyResolver maps a --policy value to a path. *config.Runtime
// implements it.
type policyResolver interface {
	ResolvePolicy(value string) string
	PolicyFile(name string) string
}

// policySource returns the source of the policy file, or nil with no
// file. A pull request scan reads a policy file of the git working tree at
// the base ref, so a change to the policy cannot loosen the gate of its
// own pull request. It never falls back to the policy of the change.
// changed is true when the change edits the policy.
func policySource(ctx context.Context, target, baseRef, value string, r policyResolver) (src plugin.PolicySource, changed bool, err error) {
	if value == "" {
		return nil, false, nil
	}
	p := r.ResolvePolicy(value)
	if baseRef == "" {
		return file.New(p), false, nil
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return nil, false, engine.ErrBaseRefTarget()
	}
	tree, err := gitbase.Open(target, baseRef)
	if err != nil {
		return nil, false, engine.BaseRefError(err)
	}
	rel, ok := tree.RepoPath(p)
	if !ok {
		return file.New(p), false, nil
	}
	fsys := tree.RepoFS()
	rel, err = baseName(fsys, rel)
	switch {
	case errors.Is(err, fs.ErrNotExist) && config.IsPolicyName(value):
		// A file that the change adds cannot take over a policy name.
		return file.New(r.PolicyFile(value)), false, nil
	case errors.Is(err, fs.ErrNotExist):
		tui.Info("vet applies no policy file, because the base ref %s has no %s", baseRef, rel)
		_, headErr := os.Stat(p)
		return nil, !errors.Is(headErr, fs.ErrNotExist), nil
	case err != nil:
		msg := fmt.Sprintf("read the policy %s at the base ref %s: %v", rel, baseRef, err)
		return nil, false, app.UsageError(msg, "Keep the policy in git as a regular file or a directory of regular files.")
	}
	label := func(name string) string { return baseRef + ":" + name }
	docs, err := file.NewFS(fsys, rel, label).Policies(ctx)
	if err != nil {
		return nil, false, err
	}
	tui.Info("vet reads the policy %s from the base ref %s", rel, baseRef)
	if changed, err = headChanged(ctx, tree.Root(), rel, label, docs); err != nil {
		return nil, false, err
	}
	if changed {
		tui.Info("This change edits %s. The gate uses the base version.", rel)
	}
	return policyDocs(docs), changed, nil
}

// baseName returns rel when the base has it. Else it returns the base
// entry whose name differs only in case, as a file system that ignores
// case finds it.
func baseName(fsys fs.FS, rel string) (string, error) {
	_, err := fs.Stat(fsys, rel)
	if !errors.Is(err, fs.ErrNotExist) {
		return rel, err
	}
	entries, dirErr := fs.ReadDir(fsys, path.Dir(rel))
	if dirErr != nil {
		return rel, err
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), path.Base(rel)) {
			folded := path.Join(path.Dir(rel), e.Name())
			_, err := fs.Stat(fsys, folded)
			return folded, err
		}
	}
	return rel, err
}

// headChanged compares the policy of the working tree with the base
// documents, by name and content. A checkout with CRLF line ends keeps the
// same policy.
func headChanged(ctx context.Context, root, rel string, label func(string) string, base []plugin.PolicyDoc) (bool, error) {
	fsys := os.DirFS(root)
	if _, err := fs.Stat(fsys, rel); errors.Is(err, fs.ErrNotExist) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	head, err := file.NewFS(fsys, rel, label).Policies(ctx)
	if err != nil {
		return false, err
	}
	return !slices.EqualFunc(base, head, func(a, b plugin.PolicyDoc) bool {
		return a.Name == b.Name && bytes.Equal(lf(a.Content), lf(b.Content))
	}), nil
}

func lf(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

// policyDocs is a policy source of documents that vet already read.
type policyDocs []plugin.PolicyDoc

func (d policyDocs) Policies(context.Context) ([]plugin.PolicyDoc, error) { return d, nil }

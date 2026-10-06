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
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// policyResolver maps a --policy value to a path. *config.Runtime
// implements it.
type policyResolver interface {
	ResolvePolicy(value string) string
	PolicyFile(name string) string
}

// policyChoice is the policy file of a scan.
type policyChoice struct {
	// Source is nil with no policy file.
	Source plugin.PolicySource
	// Changed is true when the change edits the policy.
	Changed bool
	// BaseInvalid says why the gate applies no policy file: the base
	// version does not load, and the change edits it. It is empty in each
	// other case.
	BaseInvalid string
}

// diagnostics returns the diagnostic of a base policy that does not load,
// or none.
func (c policyChoice) diagnostics() []*report.Diagnostic {
	if c.BaseInvalid == "" {
		return nil
	}
	return []*report.Diagnostic{{
		Level: report.DiagnosticWarning, Code: report.CodeBasePolicyInvalid, Component: "policy", Message: c.BaseInvalid,
	}}
}

// policySource chooses the policy file of a scan. A pull request scan
// reads a policy file of the git working tree at the base ref, so a change
// to the policy cannot loosen the gate of its own pull request. It never
// falls back to the policy of the change.
func policySource(ctx context.Context, target, baseRef, value string, r policyResolver) (policyChoice, error) {
	if value == "" {
		return policyChoice{}, nil
	}
	p := r.ResolvePolicy(value)
	if baseRef == "" {
		return policyChoice{Source: file.New(p)}, nil
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return policyChoice{}, engine.ErrBaseRefTarget()
	}
	tree, err := gitbase.Open(target, baseRef)
	if err != nil {
		return policyChoice{}, engine.BaseRefError(err)
	}
	rel, ok, err := tree.RepoPath(p)
	switch {
	case err != nil:
		msg := fmt.Sprintf("vet cannot read the policy %s at the base ref %s: %v", p, baseRef, err)
		return policyChoice{}, app.UsageError(msg, "Keep the policy in git as a regular file or a directory of regular files.")
	case !ok:
		return policyChoice{Source: file.New(p)}, nil
	}
	fsys := tree.RepoFS()
	rel, err = baseName(fsys, rel)
	switch {
	case errors.Is(err, fs.ErrNotExist) && config.IsPolicyName(value):
		// A file that the change adds cannot take over a policy name.
		return policyChoice{Source: file.New(r.PolicyFile(value))}, nil
	case errors.Is(err, fs.ErrNotExist):
		tui.Info("vet applies no policy file, because the base ref %s has no %s", baseRef, rel)
		_, headErr := os.Stat(p)
		return policyChoice{Changed: !errors.Is(headErr, fs.ErrNotExist)}, nil
	case err != nil:
		msg := fmt.Sprintf("read the policy %s at the base ref %s: %v", rel, baseRef, err)
		return policyChoice{}, app.UsageError(msg, "Keep the policy in git as a regular file or a directory of regular files.")
	}
	label := func(name string) string { return baseRef + ":" + name }
	docs, err := file.NewFS(fsys, rel, label).Policies(ctx)
	if err != nil {
		return policyChoice{}, err
	}
	tui.Info("vet reads the policy %s from the base ref %s", rel, baseRef)
	head, err := headDocs(ctx, tree.Root(), rel, label)
	if err != nil {
		return policyChoice{}, err
	}
	if head != nil && sameDocs(docs, head) {
		return policyChoice{Source: policyDocs(docs)}, nil
	}
	if _, err := policy.Load(docs); err != nil {
		return invalidBase(ctx, tree.Root(), rel, baseRef)
	}
	tui.Info("This change edits %s. The gate uses the base version.", rel)
	return policyChoice{Source: policyDocs(docs), Changed: true}, nil
}

// invalidBase chooses no policy file when the base policy does not load and
// the change edits it, as when a change moves a policy of vet v1 to v2.
// The base has no policy that works, so the change cannot loosen one. The
// policy of the change must load, so that the next pull request has a gate.
// A base policy that does not load and that the change keeps still stops
// the scan.
func invalidBase(ctx context.Context, root, rel, baseRef string) (policyChoice, error) {
	head, err := headDocs(ctx, root, rel, func(name string) string { return name })
	if err != nil {
		return policyChoice{}, err
	}
	if head != nil {
		if _, err := policy.Load(head); err != nil {
			return policyChoice{}, err
		}
	}
	msg := fmt.Sprintf("The policy %s at the base ref %s does not load, and this change edits it. "+
		"The gate applies no policy file until the change merges.", rel, baseRef)
	tui.Warning("%s", msg)
	return policyChoice{Changed: true, BaseInvalid: msg}, nil
}

// baseName returns rel when the base has it. Else it matches each part of
// rel to the base entry whose name differs only in case, as a file system
// that ignores case finds it. Two such entries make the match ambiguous,
// and baseName fails.
func baseName(fsys fs.FS, rel string) (string, error) {
	_, err := fs.Stat(fsys, rel)
	if !errors.Is(err, fs.ErrNotExist) {
		return rel, err
	}
	dir := "."
	for _, part := range strings.Split(rel, "/") {
		entries, dirErr := fs.ReadDir(fsys, dir)
		if dirErr != nil {
			return rel, err
		}
		var match string
		for _, e := range entries {
			if !strings.EqualFold(e.Name(), part) {
				continue
			}
			if match != "" {
				return rel, fmt.Errorf("the base ref has more than one entry for %s that differ only in case", path.Join(dir, part))
			}
			match = e.Name()
		}
		if match == "" {
			return rel, err
		}
		dir = path.Join(dir, match)
	}
	_, err = fs.Stat(fsys, dir)
	return dir, err
}

// headDocs reads the policy of the working tree, or nil when the change
// deletes it.
func headDocs(ctx context.Context, root, rel string, label func(string) string) ([]plugin.PolicyDoc, error) {
	fsys := os.DirFS(root)
	if _, err := fs.Stat(fsys, rel); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return file.NewFS(fsys, rel, label).Policies(ctx)
}

// sameDocs compares two policies by name and content. A checkout with CRLF
// line ends keeps the same policy.
func sameDocs(a, b []plugin.PolicyDoc) bool {
	return slices.EqualFunc(a, b, func(x, y plugin.PolicyDoc) bool {
		return x.Name == y.Name && bytes.Equal(lf(x.Content), lf(y.Content))
	})
}

func lf(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

// policyDocs is a policy source of documents that vet already read.
type policyDocs []plugin.PolicyDoc

func (d policyDocs) Policies(context.Context) ([]plugin.PolicyDoc, error) { return d, nil }

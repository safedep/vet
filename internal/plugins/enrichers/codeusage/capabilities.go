package codeusage

import (
	"cmp"
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/safedep/vet/v2/internal/gitbase"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// maxOccurrences bounds the calls that a capability lists.
const maxOccurrences = 20

// maxBaseFile is the size above which a base file is not source code
// worth an analysis, such as a bundle or a data file.
const maxBaseFile = 4 << 20

// Capabilities returns one capability for each signature that matches the
// code of the target, in id order. In pull request mode each capability
// gets its change against the base commit, and a capability of the base
// that the head does not have is removed.
func (e *Enricher) Capabilities(ctx context.Context) ([]report.Capability, error) {
	if err := e.load(ctx); err != nil {
		return nil, err
	}
	head := group(e.matches)
	if e.o.BaseRef == "" {
		return sortedCapabilities(head), nil
	}
	baseMatches, err := e.baseMatches(ctx)
	if err != nil {
		return nil, err
	}
	base := group(baseMatches)
	for id, c := range head {
		c.Change = model.ChangeAdded
		if base[id] != nil {
			c.Change = model.ChangeUnchanged
		}
	}
	for id, c := range base {
		if head[id] == nil {
			c.Change = model.ChangeRemoved
			head[id] = c
		}
	}
	return sortedCapabilities(head), nil
}

// baseMatches returns the matches of the base commit. A head file with the
// content of its base blob has the matches of the head, so only the base
// version of each changed file needs an analysis.
func (e *Enricher) baseMatches(ctx context.Context) (out []Match, err error) {
	tree, err := gitbase.Open(e.dir, e.o.BaseRef)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "vet-code-base-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()

	unchanged := map[string]bool{}
	changed := 0
	fsys := os.DirFS(e.dir)
	err = tree.Walk(ctx, func(rel string, f *object.File) error {
		if f.Size > maxBaseFile || skippedPath(rel) {
			return nil
		}
		if info, err := os.Stat(filepath.Join(e.dir, filepath.FromSlash(rel))); err == nil && info.Size() == f.Size {
			// A file that vet cannot read is changed.
			if same, err := gitbase.SameBlob(fsys, rel, f.Hash); err == nil && same {
				unchanged[rel] = true
				return nil
			}
		}
		changed++
		return gitbase.WriteBlob(f, filepath.Join(tmp, filepath.FromSlash(rel)))
	})
	if err != nil {
		return nil, err
	}

	for _, m := range e.matches {
		if unchanged[m.FilePath] {
			out = append(out, m)
		}
	}
	if changed == 0 {
		return out, nil
	}
	a, err := e.analyze(ctx, tmp)
	if err != nil {
		return nil, err
	}
	for _, m := range a.Matches {
		m.FilePath = relTo(tmp, m.FilePath)
		out = append(out, m)
	}
	return out, nil
}

// skippedPath reports a path under a directory of installed or built code.
func skippedPath(rel string) bool {
	for dir := path.Dir(rel); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if skippedDir(path.Base(dir)) {
			return true
		}
	}
	return false
}

// group makes one capability of the matches of each signature, with each
// call once, in file and line order.
func group(matches []Match) map[string]*report.Capability {
	type key struct {
		id string
		report.Occurrence
	}
	out := map[string]*report.Capability{}
	seen := map[key]bool{}
	for _, m := range matches {
		s := m.Signature
		c := out[s.ID]
		if c == nil {
			c = &report.Capability{
				ID: s.ID, Description: s.Description, Vendor: s.Vendor, Product: s.Product, Service: s.Service,
				Tags: slices.Clone(s.Tags), Occurrences: []report.Occurrence{},
			}
			out[s.ID] = c
		}
		o := report.Occurrence{File: m.FilePath, Line: m.Line, Column: m.Column, Language: m.Language, Callee: m.Callee}
		if seen[key{s.ID, o}] {
			continue
		}
		seen[key{s.ID, o}] = true
		c.Occurrences = append(c.Occurrences, o)
	}
	for _, c := range out {
		slices.SortFunc(c.Occurrences, func(a, b report.Occurrence) int {
			return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line), cmp.Compare(a.Column, b.Column), cmp.Compare(a.Callee, b.Callee))
		})
		if len(c.Occurrences) > maxOccurrences {
			c.Occurrences = c.Occurrences[:maxOccurrences]
		}
	}
	return out
}

func sortedCapabilities(m map[string]*report.Capability) []report.Capability {
	out := make([]report.Capability, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b report.Capability) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

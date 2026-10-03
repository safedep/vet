package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/safedep/dry/semver"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/gitbase"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// base is the base ref of pull request mode: the manifests that the
// extractors read from the base version of each file, and the git blob
// hash of each of those files.
type base struct {
	manifests map[string]*model.Manifest
	hashes    map[string]plumbing.Hash
}

// loadBase reads the base ref of the git working tree at dir. It writes
// each base file that an extractor wants into a temporary directory and
// extracts it there, so the base gets the same extractors as the head.
func (r *run) loadBase(ctx context.Context, a plugin.Artifact, exs []plugin.Extractor) (*base, error) {
	if a.Kind != plugin.ArtifactDirectory || a.Path == "" {
		return nil, app.UsageError("--base-ref needs a git working tree as the target", "Run vet scan in a git repository, or leave out --base-ref.")
	}
	tree, err := gitbase.Open(a.Path, r.o.BaseRef)
	switch {
	case errors.Is(err, gitbase.ErrNotRepository):
		return nil, app.UsageError(fmt.Sprintf("--base-ref: %v", err), "Run vet scan in a git repository, or leave out --base-ref.")
	case errors.Is(err, gitbase.ErrRevision):
		return nil, app.UsageError(fmt.Sprintf("--base-ref %v", err), "Fetch the base branch first, for example git fetch origin main.")
	case err != nil:
		return nil, err
	}
	hash := &tree.Commit
	cache := r.baseCache(a, *hash, exs)
	if b, ok := cache.load(); ok {
		return b, nil
	}
	tmp, err := os.MkdirTemp("", "vet-base-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			r.diags.add(report.DiagnosticWarning, CodeExtractFailed, "delta", err.Error())
		}
	}()

	b := &base{manifests: map[string]*model.Manifest{}, hashes: map[string]plumbing.Hash{}}
	var files []string
	err = tree.Walk(ctx, func(rel string, f *object.File) error {
		if r.skipped(rel) {
			return nil
		}
		if len(scalibr.Wanted(exs, rel, blobInfo{name: path.Base(rel), size: f.Size})) == 0 {
			return nil
		}
		if err := gitbase.WriteBlob(f, filepath.Join(tmp, filepath.FromSlash(rel))); err != nil {
			return err
		}
		b.hashes[rel] = f.Hash
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	failed := false
	for _, rel := range files {
		ms, errs := scalibr.ExtractFile(ctx, scalibr.File{Root: tmp, Path: rel}, exs)
		for _, err := range errs {
			// A base file that vet cannot read has no base manifest, so
			// each package of its head file is added. vet reports more,
			// not less, and says why.
			failed = true
			r.diags.add(report.DiagnosticWarning, CodeExtractFailed, "delta",
				fmt.Sprintf("read the base of %s: %v. vet compares its packages with an empty base", rel, err))
		}
		for _, m := range ms {
			m.Root = nil
			b.manifests[m.ID] = m
		}
	}
	if failed {
		// The next run tries the base again, and does not keep the error.
		return b, nil
	}
	if err := cache.save(b); err != nil {
		// A base that vet cannot keep costs one more extraction next time.
		r.diags.add(report.DiagnosticWarning, CodeExtractFailed, "delta", "keep the base extraction: "+err.Error())
	}
	return b, nil
}

// skipped reports a path under a skipped or an excluded directory.
func (r *run) skipped(rel string) bool {
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if skipDirs[part] {
			return true
		}
	}
	return r.excluded(rel)
}

// blobInfo is the file info of a base file for FileRequired.
type blobInfo struct {
	name string
	size int64
}

func (b blobInfo) Name() string     { return b.name }
func (b blobInfo) Size() int64      { return b.size }
func (blobInfo) Mode() fs.FileMode  { return 0o644 }
func (blobInfo) ModTime() time.Time { return time.Time{} }
func (blobInfo) IsDir() bool        { return false }
func (blobInfo) Sys() any           { return nil }

// diff marks the change of each package of the head manifest against the
// base manifest of the same id, and adds the packages that the base had
// and the head does not have as removed (decisions P4).
func diff(head, baseM *model.Manifest, fileChanged bool) {
	if baseM == nil {
		head.Change = model.ChangeAdded
		for _, p := range head.Packages {
			p.Change = model.ChangeAdded
		}
		return
	}
	exact := map[model.PackageID]*model.Package{}
	byName := map[model.PackageID][]string{}
	for _, p := range baseM.Packages {
		exact[p.ID] = p
		byName[p.ID.WithoutVersion()] = append(byName[p.ID.WithoutVersion()], p.ID.Version)
	}
	headVersions := map[model.PackageID]map[string]bool{}
	for _, p := range head.Packages {
		name := p.ID.WithoutVersion()
		if headVersions[name] == nil {
			headVersions[name] = map[string]bool{}
		}
		headVersions[name][p.ID.Version] = true
	}
	changed := fileChanged
	for _, p := range head.Packages {
		name := p.ID.WithoutVersion()
		switch prev := previousVersion(p.ID.Version, byName[name], headVersions[name]); {
		case exact[p.ID] != nil && sourceChanged(exact[p.ID], p):
			// The same version from another URL, with another hash or
			// with no hash: the lockfile can now install other code
			// under the same name and version.
			p.Change = model.ChangeModified
			p.PreviousResolved = exact[p.ID].Resolved
			p.PreviousIntegrity = exact[p.ID].Integrity
		case exact[p.ID] != nil:
			p.Change = model.ChangeUnchanged
		case prev != "":
			p.PreviousVersion = prev
			p.Change = model.ChangeUpgraded
			if semver.IsAhead(p.ID.Version, prev) {
				p.Change = model.ChangeDowngraded
			}
		default:
			p.Change = model.ChangeAdded
		}
		changed = changed || p.Change != model.ChangeUnchanged
	}
	for _, p := range baseM.Packages {
		if headVersions[p.ID.WithoutVersion()] == nil {
			head.Packages = append(head.Packages, &model.Package{ID: p.ID, Direct: p.Direct, Dev: p.Dev, Change: model.ChangeRemoved})
			changed = true
		}
	}
	head.Change = model.ChangeUnchanged
	if changed {
		head.Change = model.ChangeModified
	}
}

// previousVersion returns the base version that a head version replaces:
// the highest base version below it, else the lowest above it. A base
// version that the head still has replaces nothing, so a lockfile with
// two versions of a package compares each with the right one.
func previousVersion(version string, base []string, kept map[string]bool) string {
	var below, above string
	for _, v := range base {
		switch {
		case kept[v]:
		case semver.IsAhead(v, version):
			if below == "" || semver.IsAhead(below, v) {
				below = v
			}
		case above == "" || semver.IsAhead(v, above):
			above = v
		}
	}
	return cmp.Or(below, above)
}

// declaringFile maps a lockfile to the manifest file next to it.
var declaringFile = map[string]string{
	"package-lock.json": "package.json",
	"yarn.lock":         "package.json",
	"pnpm-lock.yaml":    "package.json",
	"bun.lock":          "package.json",
	"uv.lock":           "pyproject.toml",
	"poetry.lock":       "pyproject.toml",
	"pdm.lock":          "pyproject.toml",
	"Pipfile.lock":      "Pipfile",
	"Cargo.lock":        "Cargo.toml",
	"Gemfile.lock":      "Gemfile",
	"composer.lock":     "composer.json",
}

// lockfileOnly reports a changed lockfile whose manifest file is in the
// base and has not changed.
func lockfileOnly(fsys fs.FS, rel string, b *base) (bool, error) {
	decl, ok := declaringFile[path.Base(rel)]
	if !ok {
		return false, nil
	}
	sibling := path.Join(path.Dir(rel), decl)
	hash, inBase := b.hashes[sibling]
	if !inBase {
		return false, nil
	}
	if _, err := fs.Stat(fsys, sibling); err != nil {
		return false, nil
	}
	return gitbase.SameBlob(fsys, sibling, hash)
}

// sourceChanged reports a lockfile entry whose download URL, checksum or
// local mark changed with no version change. A removed checksum is a
// change, since it turns off the check of the archive.
func sourceChanged(base, head *model.Package) bool {
	return base.Resolved != head.Resolved || base.Integrity != head.Integrity && base.Integrity != "" ||
		base.Local != head.Local
}

// removed returns the base manifests that the head does not have, with
// every package removed.
func (b *base) removed(seen map[string]bool) []*model.Manifest {
	var out []*model.Manifest
	for id, m := range b.manifests {
		if seen[id] {
			continue
		}
		m.Change = model.ChangeRemoved
		for _, p := range m.Packages {
			p.Change = model.ChangeRemoved
		}
		m.Graph = nil
		out = append(out, m)
	}
	return out
}

// commitRemoved commits each removed manifest as its own unit.
func (r *run) commitRemoved(ctx context.Context, a plugin.Artifact, ms []*model.Manifest) error {
	for _, m := range ms {
		key := a.Key + "::removed::" + m.Path + "::" + m.Extractor
		if err := r.res.Scan.CommitArtifact(ctx, state.ArtifactRecord{Key: key, Kind: "removed", Path: m.Path}, []*model.Manifest{m}); err != nil {
			return err
		}
	}
	return nil
}

// introduced reports whether a finding is about something that the change
// adds or modifies. Pull request mode keeps only these findings.
func introduced(f finding.Finding, m *model.Manifest) bool {
	switch f.Subject.Kind {
	case finding.SubjectPackage:
		if f.Subject.Package == nil {
			return false
		}
		for _, p := range m.Packages {
			if p.ID.PURL() == f.Subject.Package.PURL {
				return p.Change.Introduces()
			}
		}
		return false
	case finding.SubjectFile, finding.SubjectManifest:
		return m.Change.Introduces()
	}
	return true
}

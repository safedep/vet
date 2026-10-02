package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/safedep/dry/semver"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
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
	repo, err := gogit.PlainOpenWithOptions(a.Path, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, app.UsageError(fmt.Sprintf("--base-ref: %s is not in a git repository: %v", a.Path, err), "Run vet scan in a git repository, or leave out --base-ref.")
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	prefix, err := repoPrefix(wt.Filesystem.Root(), a.Path)
	if err != nil {
		return nil, err
	}
	hash, err := repo.ResolveRevision(plumbing.Revision(r.o.BaseRef))
	if err != nil {
		return nil, app.UsageError(fmt.Sprintf("--base-ref %s: %v", r.o.BaseRef, err), "Fetch the base branch first, for example git fetch origin main.")
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
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
	err = tree.Files().ForEach(func(f *object.File) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, ok := strings.CutPrefix(f.Name, prefix)
		if !ok || rel == "" || r.skipped(rel) {
			return nil
		}
		if len(scalibr.Wanted(exs, rel, blobInfo{name: path.Base(rel), size: f.Size})) == 0 {
			return nil
		}
		if err := writeBlob(f, filepath.Join(tmp, filepath.FromSlash(rel))); err != nil {
			return err
		}
		b.hashes[rel] = f.Hash
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, rel := range files {
		ms, _ := scalibr.ExtractFile(ctx, scalibr.File{Root: tmp, Path: rel}, exs)
		for _, m := range ms {
			m.Root = nil
			b.manifests[m.ID] = m
		}
	}
	return b, nil
}

// repoPrefix returns the path of dir in the repository, with "/" and a
// trailing "/", or "" for the repository root.
func repoPrefix(repoRoot, dir string) (string, error) {
	rr, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		return "", err
	}
	d, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rr, d)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", nil
	}
	return filepath.ToSlash(rel) + "/", nil
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

func writeBlob(f *object.File, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	rd, err := f.Reader()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.Join(err, rd.Close())
	}
	_, err = io.Copy(out, rd)
	return errors.Join(err, out.Close(), rd.Close())
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

// sameBlob reports whether a head file has the content of a base blob.
// Git can check a file out with CRLF line ends and store it with LF
// (core.autocrlf), so the file also matches when its LF form does.
func sameBlob(fsys fs.FS, rel string, base plumbing.Hash) (bool, error) {
	data, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return false, err
	}
	if plumbing.ComputeHash(plumbing.BlobObject, data) == base {
		return true, nil
	}
	lf := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return len(lf) != len(data) && plumbing.ComputeHash(plumbing.BlobObject, lf) == base, nil
}

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
	exact := map[model.PackageID]bool{}
	byName := map[model.PackageID][]string{}
	for _, p := range baseM.Packages {
		exact[p.ID] = true
		byName[p.ID.WithoutVersion()] = append(byName[p.ID.WithoutVersion()], p.ID.Version)
	}
	headNames := map[model.PackageID]bool{}
	changed := fileChanged
	for _, p := range head.Packages {
		headNames[p.ID.WithoutVersion()] = true
		switch prev := byName[p.ID.WithoutVersion()]; {
		case exact[p.ID]:
			p.Change = model.ChangeUnchanged
		case len(prev) > 0:
			p.PreviousVersion = prev[0]
			p.Change = model.ChangeUpgraded
			if semver.IsAhead(p.ID.Version, prev[0]) {
				p.Change = model.ChangeDowngraded
			}
		default:
			p.Change = model.ChangeAdded
		}
		changed = changed || p.Change != model.ChangeUnchanged
	}
	for _, p := range baseM.Packages {
		if !headNames[p.ID.WithoutVersion()] {
			head.Packages = append(head.Packages, &model.Package{ID: p.ID, Direct: p.Direct, Dev: p.Dev, Change: model.ChangeRemoved})
			changed = true
		}
	}
	head.Change = model.ChangeUnchanged
	if changed {
		head.Change = model.ChangeModified
	}
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

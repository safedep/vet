package engine

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/safedep/vet/v2/internal/gitbase"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// skipDirs are the directories that a code scan does not walk. Their
// packages come from the lockfiles of the project.
var skipDirs = map[string]bool{".git": true, "node_modules": true}

var unknownPURLType = regexp.MustCompile(`unknown PURL type "([^"]+)"`)

// extract walks each artifact and commits the manifests of each file. A
// file that has not changed since a stopped run keeps its manifests.
func (r *run) extract(ctx context.Context, artifacts []plugin.Artifact) error {
	scan := r.res.Scan
	if r.res.Continued {
		if err := scan.MarkArtifactsStale(ctx); err != nil {
			return err
		}
	}
	done := 0
	for _, a := range artifacts {
		if err := r.extractSourced(ctx, a); err != nil {
			return err
		}
		var err error
		switch {
		case a.Kind == plugin.ArtifactPURL:
			err = r.extractPURL(ctx, a)
		case a.Kind == plugin.ArtifactEndpoint && len(a.Include) == 0:
			// An endpoint root is a whole file system. The engine reads
			// only the files that the source names.
		default:
			err = r.extractFiles(ctx, a, &done)
		}
		if err != nil {
			return err
		}
	}
	_, err := scan.DropStaleArtifacts(ctx)
	return err
}

// extractSourced commits the manifests and the inventory that the source
// read itself. Each manifest commits as its own artifact, keyed by its
// path, so a continued scan revives it like an extracted file.
func (r *run) extractSourced(ctx context.Context, a plugin.Artifact) error {
	scan := r.res.Scan
	for _, m := range a.Manifests {
		rec := state.ArtifactRecord{Key: a.Key + "::source::" + m.Path, Kind: string(a.Kind), Path: m.Path}
		if err := scan.CommitArtifact(ctx, rec, []*model.Manifest{m}); err != nil {
			return err
		}
	}
	if a.Kind != plugin.ArtifactEndpoint && len(a.Inventory) == 0 {
		return nil
	}
	return scan.ReplaceInventory(ctx, a.Inventory)
}

func (r *run) extractPURL(ctx context.Context, a plugin.Artifact) error {
	id, err := model.ParsePURL(a.PURL)
	if err != nil {
		return err
	}
	m := &model.Manifest{
		ID: model.ManifestID(a.PURL, "purl"), Path: a.PURL, Ecosystem: id.Ecosystem, Kind: model.ManifestKindPURL,
		Packages: []*model.Package{{ID: id, Direct: true}},
	}
	return r.res.Scan.CommitArtifact(ctx, state.ArtifactRecord{Key: a.Key, Kind: string(a.Kind), Path: a.PURL}, []*model.Manifest{m})
}

func (r *run) extractFiles(ctx context.Context, a plugin.Artifact, done *int) error {
	exs, err := r.o.Extractors(a.Kind)
	if err != nil {
		return err
	}
	fsys, err := scalibr.FileSystem(a.Path, a.Root)
	if err != nil {
		return err
	}
	var d *delta
	if r.o.BaseRef != "" {
		b, err := r.loadBase(ctx, a, exs)
		if err != nil {
			return err
		}
		d = &delta{base: b, seen: map[string]bool{}}
	}
	visit := func(rel string, info fs.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.extractFile(ctx, a, fsys, rel, info, exs, d); err != nil {
			return err
		}
		*done++
		r.o.Observer.Progress(StageExtract, *done, 0)
		return nil
	}

	if len(a.Include) > 0 {
		for _, rel := range a.Include {
			info, err := fs.Stat(fsys, rel)
			if err != nil {
				return err
			}
			if err := visit(rel, info); err != nil {
				return err
			}
		}
		return nil
	}

	if err := r.walk(fsys, a, visit); err != nil {
		return err
	}
	if d != nil {
		return r.commitRemoved(ctx, a, d.base.removed(d.seen))
	}
	return nil
}

// delta is the state of pull request mode during the walk.
type delta struct {
	base *base
	seen map[string]bool
}

func (r *run) walk(fsys fs.FS, a plugin.Artifact, visit func(string, fs.FileInfo) error) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory does not stop the scan.
			r.diags.add(report.DiagnosticWarning, CodeExtractFailed, "walk", err.Error())
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if (a.Kind == plugin.ArtifactDirectory && skipDirs[d.Name()]) || r.excluded(p) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || r.excluded(p) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		return visit(p, info)
	})
}

// excluded matches a path against the exclude patterns. A pattern matches
// the whole path, its base name, or a directory prefix of the path.
func (r *run) excluded(p string) bool {
	for _, pat := range r.o.Exclude {
		pat = strings.TrimSuffix(pat, "/")
		if ok, _ := path.Match(pat, p); ok {
			return true
		}
		if ok, _ := path.Match(pat, path.Base(p)); ok {
			return true
		}
		if strings.HasPrefix(p, pat+"/") {
			return true
		}
	}
	return false
}

func (r *run) extractFile(ctx context.Context, a plugin.Artifact, fsys fs.FS, rel string, info fs.FileInfo, exs []plugin.Extractor, d *delta) error {
	wanted := scalibr.Wanted(exs, rel, info)
	if len(wanted) == 0 && a.Kind == plugin.ArtifactSBOM {
		// The user named the file as an SBOM, so its name does not matter.
		wanted = sbomExtractors(exs)
	}
	if len(wanted) == 0 {
		return nil
	}

	scan := r.res.Scan
	key := a.Key + "::" + rel
	prev, err := scan.Artifact(ctx, key)
	if err != nil {
		return err
	}
	if prev != nil && prev.Status != state.ArtifactPending && prev.Size == info.Size() && prev.MTime.Equal(info.ModTime().Truncate(time.Millisecond)) {
		if d != nil {
			// The saved manifests already carry their change against the base.
			for _, e := range wanted {
				d.seen[model.ManifestID(rel, e.Name())] = true
			}
		}
		return scan.ReviveArtifact(ctx, key)
	}

	ms, errs := scalibr.Extract(ctx, scalibr.Input{FS: fsys, Root: a.Path, Path: rel, Info: info}, wanted)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, e := range errs {
		r.extractError(e)
	}
	if a.Kind == plugin.ArtifactEndpoint {
		// An endpoint file keeps its absolute path in the report. rootOf
		// reads it from the operating system.
		for _, m := range ms {
			m.Path = filepath.ToSlash(filepath.Join(a.Path, filepath.FromSlash(rel)))
		}
	}
	if d != nil {
		baseHash, inBase := d.base.hashes[rel]
		same := false
		if inBase {
			var err error
			if same, err = gitbase.SameBlob(fsys, rel, baseHash); err != nil {
				return err
			}
		}
		for _, m := range ms {
			diff(m, d.base.manifests[m.ID], !same)
			d.seen[m.ID] = true
		}
		if !same && inBase {
			only, err := lockfileOnly(fsys, rel, d.base)
			if err != nil {
				return err
			}
			for _, m := range ms {
				m.LockfileOnly = only && m.Kind == model.ManifestKindLockfile
			}
		}
	}
	return scan.CommitArtifact(ctx, state.ArtifactRecord{
		Key: key, Kind: string(a.Kind), Path: rel, Size: info.Size(), MTime: info.ModTime(),
	}, ms)
}

func (r *run) extractError(err error) {
	// gap G3: the OS packages of an image (deb, apk, rpm) and ecosystems
	// such as Conan or Hex have no vet ecosystem and no Insights v2 data.
	// The scan skips them with one diagnostic for each ecosystem.
	if m := unknownPURLType.FindStringSubmatch(err.Error()); m != nil {
		r.diags.add(report.DiagnosticWarning, CodeUnknownEcosystem, "extract",
			fmt.Sprintf("vet has no data for the %s ecosystem, so it skips its packages", m[1]))
		return
	}
	r.diags.add(report.DiagnosticWarning, CodeExtractFailed, "extract", err.Error())
}

func sbomExtractors(exs []plugin.Extractor) []plugin.Extractor {
	var out []plugin.Extractor
	for _, e := range exs {
		if strings.HasPrefix(e.Name(), "sbom/") {
			out = append(out, e)
		}
	}
	return out
}

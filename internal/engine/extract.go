package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/safedep/vet/v2/internal/gitbase"
	"github.com/safedep/vet/v2/internal/plugins/extractors/installed"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// skipDirs are the directories that a code scan does not walk. Their
// packages come from the lockfiles of the project. A scan that reads
// installed packages walks node_modules.
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
		ID: model.ManifestID(a.PURL, "purl"), Path: a.PURL, Ecosystem: id.Ecosystem(), Kind: model.ManifestKindPURL,
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

	if err := r.walk(fsys, a, slices.ContainsFunc(exs, scalibr.ReadsInstalled), visit); err != nil {
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

func (r *run) walk(fsys fs.FS, a plugin.Artifact, readsInstalled bool, visit func(string, fs.FileInfo) error) error {
	systemDir := systemDirs(a)
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory does not stop the scan.
			r.diags.add(report.DiagnosticWarning, report.CodeExtractFailed, "walk", readError(err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == "." {
			if systemDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if r.excluded(p) || systemDir(p) {
				return fs.SkipDir
			}
			if !readsInstalled && a.Kind == plugin.ArtifactDirectory && installed.IsInstallDir(d.Name()) && r.res.Installed == "" {
				r.res.Installed = p
			}
			if skipDir(a, d.Name(), readsInstalled) {
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

// skipDir reports a directory of a directory artifact that the walk does
// not enter.
func skipDir(a plugin.Artifact, name string, readsInstalled bool) bool {
	if a.Kind != plugin.ArtifactDirectory || !skipDirs[name] {
		return false
	}
	return name != "node_modules" || !readsInstalled
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
	var inBase, same bool
	if d != nil {
		if baseHash, ok := d.base.hashes[rel]; ok {
			inBase = true
			if same, err = gitbase.SameBlob(fsys, rel, baseHash); err != nil {
				return err
			}
		}
	}
	for _, e := range errs {
		r.extractError(e, fileChange(d != nil, inBase, same))
	}
	if a.Kind == plugin.ArtifactEndpoint {
		// An endpoint file keeps its absolute path in the report. rootOf
		// reads it from the operating system.
		for _, m := range ms {
			m.Path = filepath.ToSlash(filepath.Join(a.Path, filepath.FromSlash(rel)))
		}
	}
	if d != nil {
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

// fileChange is the change of a file against the base, or none outside
// pull request mode.
func fileChange(delta, inBase, same bool) model.Change {
	switch {
	case !delta:
		return model.ChangeNone
	case !inBase:
		return model.ChangeAdded
	case same:
		return model.ChangeUnchanged
	}
	return model.ChangeModified
}

func (r *run) extractError(err error, change model.Change) {
	// gap G3: the OS packages of an image (deb, apk, rpm) and ecosystems
	// such as Conan or Hex have no vet ecosystem and no Insights v2 data.
	// The scan skips them with one diagnostic for each ecosystem.
	if m := unknownPURLType.FindStringSubmatch(err.Error()); m != nil {
		r.diags.add(report.DiagnosticWarning, report.CodeUnknownEcosystem, "extract",
			fmt.Sprintf("vet has no data for the %s ecosystem, so it skips its packages", m[1]))
		return
	}
	r.diags.put(&report.Diagnostic{
		Level: report.DiagnosticWarning, Code: report.CodeExtractFailed, Component: "extract", Message: readError(err), Change: change,
	})
}

// permissionDenied is the one message of every path that the user cannot
// read, so the diagnostics collapse into one with a count. A scan of a
// root file system meets many.
const permissionDenied = "vet skipped the paths that the user cannot read"

func readError(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return permissionDenied
	}
	return err.Error()
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

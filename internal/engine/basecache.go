package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// baseDir is the directory of the base extractions in the state directory.
const baseDir = "bases"

// keepBases is the number of base extractions that vet keeps for each
// target. A pull request that gets new commits on the same base reuses
// its base.
const keepBases = 3

// baseCache keeps the base extraction of pull request mode for a target
// and a base commit. The extraction depends only on the commit, the
// extractors and the vet version, so a second run on the same base reads
// it back and does not extract again.
type baseCache struct {
	dir    string
	target string
	path   string
}

func (r *run) baseCache(a plugin.Artifact, commit plumbing.Hash, exs []plugin.Extractor) baseCache {
	names := make([]string, 0, len(exs))
	for _, e := range exs {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	target := hashOf(a.Key)
	key := hashOf(strings.Join(append([]string{a.Key, commit.String(), r.o.VetVersion, r.o.OptionsHash}, names...), "\x00"))
	dir := filepath.Join(r.o.Store.StateDir(), baseDir)
	return baseCache{dir: dir, target: target, path: filepath.Join(dir, target+"-"+key+".json")}
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// baseFile is the stored form of a base. A manifest keeps its packages,
// which the model leaves out of its JSON.
type baseFile struct {
	Manifests []baseManifest    `json:"manifests"`
	Hashes    map[string]string `json:"hashes"`
}

type baseManifest struct {
	Manifest model.Manifest  `json:"manifest"`
	Packages []model.Package `json:"packages"`
}

func (c baseCache) load() (*base, bool) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, false
	}
	var f baseFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, false
	}
	b := &base{manifests: map[string]*model.Manifest{}, hashes: map[string]plumbing.Hash{}}
	for i := range f.Manifests {
		m := f.Manifests[i].Manifest
		for j := range f.Manifests[i].Packages {
			m.Packages = append(m.Packages, &f.Manifests[i].Packages[j])
		}
		b.manifests[m.ID] = &m
	}
	for rel, h := range f.Hashes {
		b.hashes[rel] = plumbing.NewHash(h)
	}
	return b, true
}

func (c baseCache) save(b *base) error {
	f := baseFile{Hashes: map[string]string{}}
	ids := make([]string, 0, len(b.manifests))
	for id := range b.manifests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m := b.manifests[id]
		bm := baseManifest{Manifest: *m}
		bm.Manifest.Packages, bm.Manifest.Graph = nil, nil
		for _, p := range m.Packages {
			bm.Packages = append(bm.Packages, *p)
		}
		f.Manifests = append(f.Manifests, bm)
	}
	for rel, h := range b.hashes {
		f.Hashes[rel] = h.String()
	}
	data, err := json.Marshal(&f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return err
	}
	return c.prune()
}

// prune keeps the newest bases of the target.
func (c baseCache) prune() error {
	matches, err := filepath.Glob(filepath.Join(c.dir, c.target+"-*.json"))
	if err != nil {
		return err
	}
	type file struct {
		path string
		mod  int64
	}
	var files []file
	for _, m := range matches {
		info, err := os.Stat(m)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		files = append(files, file{m, info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	var errs []error
	for _, f := range files[min(keepBases, len(files)):] {
		if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

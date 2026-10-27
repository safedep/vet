package codeusage

import (
	"context"
	"encoding/json"
	"maps"
	"sync"

	"github.com/safedep/code/fileindex"
	"github.com/safedep/code/fileindex/store"
	"github.com/safedep/dry/log"
)

// moduleStore keeps the module graph cache of each module version in one
// artifact. modgraph asks the store about each package on its own, and one
// SQLite call for each package costs more than a read of its files. A
// module version holds many packages, so a scan reads its artifact once and
// writes it once. A key with no package unit goes to the store as it is.
//
// A store that fails costs time, not the graph: a read that fails is a
// miss, and a write that fails is lost.
type moduleStore struct {
	store.Store

	mu      sync.Mutex
	modules map[store.ArtifactKey]*moduleEntry
}

// moduleEntry is the cache of one module version: the artifact of each
// package, by its directory in the module.
type moduleEntry struct {
	Packages map[string]json.RawMessage `json:"packages"`
	dirty    bool
}

// modulePlugin names the artifacts of moduleStore, apart from those of
// modgraph.
const modulePlugin = "vet-module"

func newModuleStore(st store.Store) *moduleStore {
	return &moduleStore{Store: st, modules: map[store.ArtifactKey]*moduleEntry{}}
}

// moduleKey returns the key of the module version of a package key, and
// the directory of the package in it.
func moduleKey(k store.ArtifactKey) (store.ArtifactKey, string, bool) {
	unit, dir := fileindex.SplitUnit(k.Path)
	if unit == "" {
		return store.ArtifactKey{}, "", false
	}
	mk := k
	mk.Path = unit
	mk.Plugin = modulePlugin + "/" + k.Plugin
	return mk, dir, true
}

// GetArtifacts answers a package key from the artifact of its module.
func (s *moduleStore) GetArtifacts(ctx context.Context, keys []store.ArtifactKey) (map[store.ArtifactKey][]byte, error) {
	out := map[store.ArtifactKey][]byte{}
	var others []store.ArtifactKey
	s.mu.Lock()
	for _, k := range keys {
		mk, dir, ok := moduleKey(k)
		if !ok {
			others = append(others, k)
			continue
		}
		if data, ok := s.load(ctx, mk).Packages[dir]; ok {
			out[k] = data
		}
	}
	s.mu.Unlock()
	if len(others) == 0 {
		return out, nil
	}
	found, err := s.Store.GetArtifacts(ctx, others)
	if err != nil {
		return nil, err
	}
	maps.Copy(out, found)
	return out, nil
}

// PutArtifacts keeps the artifact of a package in its module until Flush.
func (s *moduleStore) PutArtifacts(ctx context.Context, artifacts []store.Artifact) error {
	var others []store.Artifact
	s.mu.Lock()
	for _, a := range artifacts {
		mk, dir, ok := moduleKey(a.Key)
		if !ok {
			others = append(others, a)
			continue
		}
		e := s.load(ctx, mk)
		e.Packages[dir] = a.Data
		e.dirty = true
	}
	s.mu.Unlock()
	if len(others) == 0 {
		return nil
	}
	return s.Store.PutArtifacts(ctx, others)
}

// load returns the entry of a module version, read from the store once.
func (s *moduleStore) load(ctx context.Context, mk store.ArtifactKey) *moduleEntry {
	if e, ok := s.modules[mk]; ok {
		return e
	}
	e := &moduleEntry{}
	found, err := s.Store.GetArtifacts(ctx, []store.ArtifactKey{mk})
	if err != nil {
		log.Warnf("module graph cache: read %s: %v", mk.Path, err)
	} else if data, ok := found[mk]; ok {
		if err := json.Unmarshal(data, e); err != nil {
			log.Debugf("module graph cache: %s: %v. vet reads the module again", mk.Path, err)
		}
	}
	if e.Packages == nil {
		e.Packages = map[string]json.RawMessage{}
	}
	s.modules[mk] = e
	return e
}

// Flush writes the entry of each module version that a put changed, in one
// call.
func (s *moduleStore) Flush(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var batch []store.Artifact
	for mk, e := range s.modules {
		if !e.dirty {
			continue
		}
		data, err := json.Marshal(e)
		if err != nil {
			log.Warnf("module graph cache: encode %s: %v", mk.Path, err)
			continue
		}
		batch = append(batch, store.Artifact{Key: mk, Data: data})
	}
	if len(batch) == 0 {
		return
	}
	if err := s.Store.PutArtifacts(ctx, batch); err != nil {
		log.Warnf("module graph cache: write %d modules: %v", len(batch), err)
		return
	}
	for _, a := range batch {
		s.modules[a.Key].dirty = false
	}
}

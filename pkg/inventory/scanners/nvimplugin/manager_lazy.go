package nvimplugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	managerLazy      = "lazy.nvim"
	lazyLockfileName = "lazy-lock.json"
	lazyPluginSubdir = "lazy"
)

// lazyManager discovers plugins under stdpath("data")/lazy, overlaying
// lazy-lock.json for declared state.
type lazyManager struct{}

func newLazyManager() Manager { return &lazyManager{} }

func (m *lazyManager) Name() string { return managerLazy }

// Discover enumerates installed clones under <data>/lazy and overlays the
// declared state from <config>/lazy-lock.json. On-disk state is primary;
// the lock file adds only the declared flag and pinned commit/branch. A
// malformed lock file degrades to installed-only discovery.
func (m *lazyManager) Discover(_ context.Context, env Env) ([]Plugin, error) {
	lazyRoot := filepath.Join(env.DataDir, lazyPluginSubdir)
	lockPath := filepath.Join(env.ConfigDir, lazyLockfileName)

	plugins, err := m.discoverInstalled(lazyRoot, lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No install root yet, but a dotfiles repo can still declare
			// plugins before the first :Lazy sync — overlay the lock file.
			plugins = map[string]*Plugin{}
		} else {
			return nil, fmt.Errorf("lazy: read plugin root %s: %w", lazyRoot, err)
		}
	}

	var errs []error
	lock, lockErr := readLockfile(lockPath)
	if lockErr != nil {
		errs = append(errs, fmt.Errorf("lazy: read lock file %s: %w", lockPath, lockErr))
	}
	overlayLock(plugins, lock, lazyRoot, lockPath)

	out := make([]Plugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out, errors.Join(errs...)
}

// discoverInstalled reads each subdirectory of lazyRoot as an installed
// plugin, keyed by install-dir base name. os.ErrNotExist is propagated so
// the caller can distinguish "no lazy" from a real read failure.
func (m *lazyManager) discoverInstalled(lazyRoot, lockPath string) (map[string]*Plugin, error) {
	entries, err := os.ReadDir(lazyRoot)
	if err != nil {
		return nil, err
	}

	plugins := make(map[string]*Plugin, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		installDir := filepath.Join(lazyRoot, name)
		clone := readGitClone(installDir)
		info := normalizeRepoURL(clone.OriginURL)

		plugins[name] = &Plugin{
			Name:       name,
			Repository: info.Repository,
			Ecosystem:  info.Ecosystem,
			Owner:      info.Owner,
			Repo:       info.Repo,
			Commit:     clone.Head,
			InstallDir: installDir,
			SourcePath: lockPath,
			Installed:  true,
		}
	}
	return plugins, nil
}

// overlayLock marks locked plugins as declared with their pinned
// commit/branch, adding a declared-but-not-installed entry for any lock
// key with no clone on disk.
func overlayLock(plugins map[string]*Plugin, lock map[string]lockEntry, lazyRoot, lockPath string) {
	for name, entry := range lock {
		p, ok := plugins[name]
		if !ok {
			p = &Plugin{
				Name:       name,
				InstallDir: filepath.Join(lazyRoot, name),
				SourcePath: lockPath,
			}
			plugins[name] = p
		}
		p.Declared = true
		p.LockCommit = entry.Commit
		p.LockBranch = entry.Branch
	}
}

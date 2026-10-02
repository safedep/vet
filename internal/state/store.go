package state

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/report"
)

// Options open the local state.
type Options struct {
	StateDir string
	CacheDir string
}

// Store is the local state: the scan index and the scan files.
type Store struct {
	stateDir string
	cacheDir string
	index    *Index
}

// Open opens the scan index in the state directory and creates the
// directory with mode 0700 when it does not exist.
func Open(ctx context.Context, o Options) (*Store, error) {
	if err := appdir.Ensure(o.StateDir); err != nil {
		return nil, err
	}
	idx, err := openIndex(ctx, o.StateDir)
	if err != nil {
		return nil, err
	}
	return &Store{stateDir: o.StateDir, cacheDir: o.CacheDir, index: idx}, nil
}

// Close closes the scan index.
func (s *Store) Close() error { return s.index.Close() }

// Index returns the scan index.
func (s *Store) Index() *Index { return s.index }

// StateDir returns the state directory.
func (s *Store) StateDir() string { return s.stateDir }

// CacheDir returns the cache directory.
func (s *Store) CacheDir() string { return s.cacheDir }

// ScansDir returns the directory of the scan files.
func (s *Store) ScansDir() string { return filepath.Join(s.stateDir, "scans") }

// NewScan describes a scan to create.
type NewScan struct {
	TargetKey   string
	TargetLabel string
	Kind        report.ScanKind
	OptionsHash string
	VetVersion  string
	Host        string
	PID         int
}

// CreateScan makes a scan id, creates and locks its scan file, and adds a
// running entry to the index. Close on the scan releases the lock.
func (s *Store) CreateScan(ctx context.Context, n NewScan) (*Scan, *IndexEntry, error) {
	if err := appdir.Ensure(s.ScansDir()); err != nil {
		return nil, nil, err
	}
	id, err := NewScanID()
	if err != nil {
		return nil, nil, err
	}
	scan, err := openScanFile(ctx, s.ScansDir(), id)
	if err != nil {
		return nil, nil, err
	}
	if scan.lock, err = acquireLock(scan.Path()); err != nil {
		return nil, nil, errors.Join(err, scan.Close())
	}
	now := time.Now().UTC()
	e := &IndexEntry{
		ID: id, TargetKey: n.TargetKey, TargetLabel: n.TargetLabel, Kind: string(n.Kind),
		Status: StatusRunning, OptionsHash: n.OptionsHash, VetVersion: n.VetVersion,
		SchemaVersion: report.SchemaVersion, StartedAt: now, UpdatedAt: now,
		File: scan.Path(), PID: n.PID, Host: n.Host,
	}
	if err := s.index.insert(ctx, e); err != nil {
		return nil, nil, errors.Join(err, scan.Close())
	}
	return scan, e, nil
}

// OpenScan opens the scan file of an index entry.
func (s *Store) OpenScan(ctx context.Context, e *IndexEntry) (*Scan, error) {
	if _, err := os.Stat(e.File); err != nil {
		return nil, fmt.Errorf("scan %s: the scan file %s is missing: %w", e.ID, e.File, err)
	}
	return openScanFile(ctx, filepath.Dir(e.File), e.ID)
}

// OpenScanFile opens a scan file by its path, for "vet report show FILE".
func OpenScanFile(ctx context.Context, path string) (*Scan, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("scan file %s: %w", path, err)
	}
	base := filepath.Base(path)
	return openScanFile(ctx, filepath.Dir(path), base[:len(base)-len(filepath.Ext(base))])
}

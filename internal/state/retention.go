package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ErrScanRunning means that a live process holds the scan.
var ErrScanRunning = errors.New("state: a vet process runs the scan")

// Retention holds the rules that delete old scans at the end of each scan
// (scan state design, section 6).
type Retention struct {
	// PerTarget is the number of completed scans to keep for each target.
	// Zero keeps every scan.
	PerTarget int
	// Interrupted is the age after which an interrupted or failed scan
	// goes. Zero keeps them.
	Interrupted time.Duration
	// MaxSize is the size limit of all scans. Zero has no limit.
	MaxSize int64
}

// Select returns the scans that the rules delete now, the oldest first. It
// never selects a running scan or the last completed scan of a target.
// entries must be the newest first, as List returns them.
func (r Retention) Select(entries []*IndexEntry, now time.Time) []*IndexEntry {
	drop := map[string]bool{}
	kept := map[string]int{}
	lastCompleted := map[string]string{}
	for _, e := range entries {
		switch e.Status {
		case StatusRunning:
			continue
		case StatusCompleted:
			if _, ok := lastCompleted[e.TargetKey]; !ok {
				lastCompleted[e.TargetKey] = e.ID
			}
			kept[e.TargetKey]++
			if r.PerTarget > 0 && kept[e.TargetKey] > r.PerTarget {
				drop[e.ID] = true
			}
		default:
			if r.Interrupted > 0 && now.Sub(e.UpdatedAt) > r.Interrupted {
				drop[e.ID] = true
			}
		}
	}

	if r.MaxSize > 0 {
		var total int64
		for _, e := range entries {
			if !drop[e.ID] {
				total += e.SizeBytes
			}
		}
		for i := len(entries) - 1; i >= 0 && total > r.MaxSize; i-- {
			e := entries[i]
			if drop[e.ID] || e.Status == StatusRunning || lastCompleted[e.TargetKey] == e.ID {
				continue
			}
			drop[e.ID] = true
			total -= e.SizeBytes
		}
	}

	var out []*IndexEntry
	for i := len(entries) - 1; i >= 0; i-- {
		if drop[entries[i].ID] {
			out = append(out, entries[i])
		}
	}
	return out
}

// ApplyRetention deletes the scans that the rules select and returns them.
func (s *Store) ApplyRetention(ctx context.Context, r Retention, now time.Time) ([]*IndexEntry, error) {
	entries, err := s.index.List(ctx, ListOptions{})
	if err != nil {
		return nil, err
	}
	s.refreshSizes(entries)
	var deleted []*IndexEntry
	for _, e := range r.Select(entries, now) {
		if err := s.DeleteScan(ctx, e); err != nil {
			if errors.Is(err, ErrScanRunning) {
				continue
			}
			return deleted, err
		}
		deleted = append(deleted, e)
	}
	return deleted, nil
}

// refreshSizes sets the size of each entry from its files, because a scan
// that did not finish has no size in the index.
func (s *Store) refreshSizes(entries []*IndexEntry) {
	for _, e := range entries {
		if n := filesSize(scanFiles(e.File)); n > 0 {
			e.SizeBytes = n
		}
	}
}

// DeleteScan deletes the scan file, its journal and its lock, and the
// index entry. A scan that a live process holds stays.
func (s *Store) DeleteScan(ctx context.Context, e *IndexEntry) error {
	if e.Status == StatusRunning {
		live, err := isLive(e.File)
		if err != nil {
			return err
		}
		if live {
			return fmt.Errorf("scan %s: %w", e.ID, ErrScanRunning)
		}
	}
	if err := removeFiles(scanFiles(e.File)); err != nil {
		return fmt.Errorf("delete scan %s: %w", e.ID, err)
	}
	return s.index.Delete(ctx, e.ID)
}

// Usage sums the scans of the index.
type Usage struct {
	Scans       int
	Targets     int
	Bytes       int64
	Interrupted []*IndexEntry
}

// Usage returns the counts and the size of the scans.
func (s *Store) Usage(ctx context.Context) (*Usage, error) {
	entries, err := s.index.List(ctx, ListOptions{})
	if err != nil {
		return nil, err
	}
	s.refreshSizes(entries)
	u := &Usage{Scans: len(entries)}
	targets := map[string]bool{}
	for _, e := range entries {
		targets[e.TargetKey] = true
		u.Bytes += e.SizeBytes
		if e.Status == StatusInterrupted {
			u.Interrupted = append(u.Interrupted, e)
		}
	}
	u.Targets = len(targets)
	return u, nil
}

// scanFiles are the files of a scan: the database, its journal and its
// lock.
func scanFiles(file string) []string {
	return []string{file, file + "-wal", file + "-shm", lockPath(file)}
}

// CacheFiles are the files of the enrichment cache in a directory.
func CacheFiles(dir string) []string {
	f := filepath.Join(dir, "cache.db")
	return []string{f, f + "-wal", f + "-shm"}
}

// FilesSize sums the size of the files that exist.
func FilesSize(paths []string) int64 { return filesSize(paths) }

func filesSize(paths []string) int64 {
	var n int64
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			n += info.Size()
		}
	}
	return n
}

// RemoveFiles deletes the files that exist.
func RemoveFiles(paths []string) error { return removeFiles(paths) }

func removeFiles(paths []string) error {
	var errs []error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

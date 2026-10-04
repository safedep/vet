package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/usefulerror"
)

// Issues are the problems of the state that "vet doctor --fix" repairs.
type Issues struct {
	// StaleRunning are scans marked running whose process stopped.
	StaleRunning []*IndexEntry
	// MissingFiles are index entries whose scan file is gone.
	MissingFiles []*IndexEntry
	// Orphans are scan files with no index entry.
	Orphans []string
}

// Empty reports whether the state has no issue.
func (i *Issues) Empty() bool {
	return len(i.StaleRunning) == 0 && len(i.MissingFiles) == 0 && len(i.Orphans) == 0
}

// Inspect finds the issues of the state. It changes nothing.
func (s *Store) Inspect(ctx context.Context) (*Issues, error) {
	entries, err := s.index.List(ctx, ListOptions{})
	if err != nil {
		return nil, err
	}
	out := &Issues{}
	known := map[string]bool{}
	for _, e := range entries {
		known[filepath.Clean(e.File)] = true
		if _, err := os.Stat(e.File); errors.Is(err, fs.ErrNotExist) {
			out.MissingFiles = append(out.MissingFiles, e)
			continue
		}
		if e.Status != StatusRunning {
			continue
		}
		live, err := isLive(e.File)
		if err != nil {
			return nil, err
		}
		if !live {
			out.StaleRunning = append(out.StaleRunning, e)
		}
	}
	files, err := filepath.Glob(filepath.Join(s.ScansDir(), "*.db"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !known[filepath.Clean(f)] {
			out.Orphans = append(out.Orphans, f)
		}
	}
	return out, nil
}

// Repair fixes the issues: it marks a stale running scan interrupted,
// removes an entry whose file is gone, and adds an entry for an orphan
// scan file from its header. It deletes an orphan scan file of another
// format, because this vet cannot read it and does not migrate it. It
// deletes no other scan file.
func (s *Store) Repair(ctx context.Context, i *Issues) error {
	var errs []error
	for _, e := range i.StaleRunning {
		errs = append(errs, s.markInterrupted(ctx, e))
	}
	for _, e := range i.MissingFiles {
		errs = append(errs, s.index.Delete(ctx, e.ID))
	}
	for _, f := range i.Orphans {
		errs = append(errs, s.indexOrphan(ctx, f))
	}
	return errors.Join(errs...)
}

func (s *Store) indexOrphan(ctx context.Context, file string) (err error) {
	id := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	scan, err := openCurrentScanFile(ctx, filepath.Dir(file), id)
	if ue, ok := usefulerror.AsUsefulError(err); ok && ue.Code() == CodeScanFormat {
		return os.Remove(file)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, scan.Close()) }()
	h := scan.Header()
	if h == nil {
		return fmt.Errorf("scan file %s has no header", file)
	}
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	e := &IndexEntry{
		ID: id, TargetKey: h.Scan.TargetKey, TargetLabel: h.Scan.Target, Kind: string(h.Scan.Kind),
		Status: StatusInterrupted, VetVersion: h.Tool.Version, SchemaVersion: h.SchemaVersion,
		StartedAt: h.Scan.StartedAt, UpdatedAt: info.ModTime().UTC(), File: file, SizeBytes: info.Size(),
	}
	if t := scan.Trailer(); t != nil {
		e.Status, e.FinishedAt, e.Gate = StatusCompleted, t.FinishedAt, string(t.Gate.Outcome)
		e.Packages, e.Findings = t.Summary.Packages, t.Summary.Findings
	}
	return s.index.insert(ctx, e)
}

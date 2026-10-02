package state

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
)

// Status is the status of a scan in the index.
type Status string

const (
	StatusRunning     Status = "running"
	StatusInterrupted Status = "interrupted"
	StatusCompleted   Status = "completed"
	StatusFailed      Status = "failed"
)

// ErrNotFound means that no scan matches.
var ErrNotFound = errors.New("state: scan not found")

// IndexEntry is one row of the scan index.
type IndexEntry struct {
	ID            string
	TargetKey     string
	TargetLabel   string
	Kind          string
	Status        Status
	OptionsHash   string
	VetVersion    string
	SchemaVersion string
	StartedAt     time.Time
	UpdatedAt     time.Time
	FinishedAt    time.Time
	Packages      int
	Findings      int
	Gate          string
	File          string
	SizeBytes     int64
	PID           int
	Host          string
	// Continued reports that a run continued the scan after an interrupt.
	Continued bool
	// RunTime is the sum of the run times of the scan.
	RunTime time.Duration
}

var indexMigrations = []string{
	`CREATE TABLE vet_scans (
		id             TEXT PRIMARY KEY,
		target_key     TEXT NOT NULL,
		target_label   TEXT NOT NULL,
		kind           TEXT NOT NULL,
		status         TEXT NOT NULL,
		options_hash   TEXT NOT NULL,
		vet_version    TEXT NOT NULL,
		schema_version TEXT NOT NULL,
		started_at     INTEGER NOT NULL,
		updated_at     INTEGER NOT NULL,
		finished_at    INTEGER NOT NULL DEFAULT 0,
		packages       INTEGER NOT NULL DEFAULT 0,
		findings       INTEGER NOT NULL DEFAULT 0,
		gate           TEXT NOT NULL DEFAULT '',
		file           TEXT NOT NULL,
		size_bytes     INTEGER NOT NULL DEFAULT 0,
		pid            INTEGER NOT NULL DEFAULT 0,
		host           TEXT NOT NULL DEFAULT '',
		continued      INTEGER NOT NULL DEFAULT 0,
		run_time_ms    INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX vet_scans_target_started ON vet_scans (target_key, started_at)`,
}

// Index is the scan index in vet.db.
type Index struct {
	mgr localdb.FileManager
	db  *sql.DB
}

func openIndex(ctx context.Context, dir string) (*Index, error) {
	mgr := openFile(dir, "vet.db")
	st, err := mgr.Store(ctx, localdb.Descriptor{Name: "vet_scans", Migrations: indexMigrations})
	if err != nil {
		return nil, fmt.Errorf("open scan index: %w", err)
	}
	return &Index{mgr: mgr, db: st.DB()}, nil
}

// Close closes vet.db.
func (x *Index) Close() error { return x.mgr.Close() }

// Path returns the path of vet.db.
func (x *Index) Path() string { return x.mgr.Path() }

const indexColumns = `id, target_key, target_label, kind, status, options_hash, vet_version, schema_version,
	started_at, updated_at, finished_at, packages, findings, gate, file, size_bytes, pid, host, continued, run_time_ms`

func (x *Index) insert(ctx context.Context, e *IndexEntry) error {
	_, err := x.db.ExecContext(ctx, `INSERT INTO vet_scans (`+indexColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TargetKey, e.TargetLabel, e.Kind, string(e.Status), e.OptionsHash, e.VetVersion, e.SchemaVersion,
		unixMilli(e.StartedAt), unixMilli(e.UpdatedAt), unixMilli(e.FinishedAt), e.Packages, e.Findings, e.Gate,
		e.File, e.SizeBytes, e.PID, e.Host, boolInt(e.Continued), e.RunTime.Milliseconds())
	if err != nil {
		return fmt.Errorf("index scan %s: %w", e.ID, err)
	}
	return nil
}

// Update writes every column of an entry.
func (x *Index) Update(ctx context.Context, e *IndexEntry) error {
	res, err := x.db.ExecContext(ctx, `UPDATE vet_scans SET target_key = ?, target_label = ?, kind = ?, status = ?,
		options_hash = ?, vet_version = ?, schema_version = ?, started_at = ?, updated_at = ?, finished_at = ?,
		packages = ?, findings = ?, gate = ?, file = ?, size_bytes = ?, pid = ?, host = ?, continued = ?, run_time_ms = ?
		WHERE id = ?`,
		e.TargetKey, e.TargetLabel, e.Kind, string(e.Status), e.OptionsHash, e.VetVersion, e.SchemaVersion,
		unixMilli(e.StartedAt), unixMilli(e.UpdatedAt), unixMilli(e.FinishedAt), e.Packages, e.Findings, e.Gate,
		e.File, e.SizeBytes, e.PID, e.Host, boolInt(e.Continued), e.RunTime.Milliseconds(), e.ID)
	if err != nil {
		return fmt.Errorf("update scan %s: %w", e.ID, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns the entry of a scan id.
func (x *Index) Get(ctx context.Context, id string) (*IndexEntry, error) {
	row := x.db.QueryRowContext(ctx, `SELECT `+indexColumns+` FROM vet_scans WHERE id = ?`, id)
	e, err := scanEntry(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// Find returns the scan whose id starts with a prefix. Two matches is an error.
func (x *Index) Find(ctx context.Context, prefix string) (*IndexEntry, error) {
	rows, err := x.db.QueryContext(ctx, `SELECT `+indexColumns+` FROM vet_scans WHERE id LIKE ? ESCAPE '\' ORDER BY id LIMIT 2`,
		escapeLike(prefix)+"%")
	if err != nil {
		return nil, fmt.Errorf("find scan %s: %w", prefix, err)
	}
	entries, err := collect(rows)
	if err != nil {
		return nil, err
	}
	switch len(entries) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return entries[0], nil
	}
	return nil, fmt.Errorf("scan id %q matches more than one scan: type more characters", prefix)
}

// ListOptions select entries from the index.
type ListOptions struct {
	// TargetKey selects one target. Empty selects every target.
	TargetKey string
	Statuses  []Status
	Limit     int
}

// List returns entries, the newest first.
func (x *Index) List(ctx context.Context, o ListOptions) ([]*IndexEntry, error) {
	q := `SELECT ` + indexColumns + ` FROM vet_scans WHERE 1 = 1`
	var args []any
	if o.TargetKey != "" {
		q += ` AND target_key = ?`
		args = append(args, o.TargetKey)
	}
	if len(o.Statuses) > 0 {
		q += ` AND status IN (?` + repeat(",?", len(o.Statuses)-1) + `)`
		for _, s := range o.Statuses {
			args = append(args, string(s))
		}
	}
	q += ` ORDER BY started_at DESC, id DESC`
	if o.Limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, o.Limit)
	}
	rows, err := x.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	return collect(rows)
}

// Delete removes an entry.
func (x *Index) Delete(ctx context.Context, id string) error {
	if _, err := x.db.ExecContext(ctx, `DELETE FROM vet_scans WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete scan %s: %w", id, err)
	}
	return nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanEntry(r rowScanner) (*IndexEntry, error) {
	var (
		e                               IndexEntry
		status                          string
		started, updated, finished, run int64
		continued                       int
	)
	if err := r.Scan(&e.ID, &e.TargetKey, &e.TargetLabel, &e.Kind, &status, &e.OptionsHash, &e.VetVersion, &e.SchemaVersion,
		&started, &updated, &finished, &e.Packages, &e.Findings, &e.Gate, &e.File, &e.SizeBytes, &e.PID, &e.Host,
		&continued, &run); err != nil {
		return nil, err
	}
	e.Status = Status(status)
	e.StartedAt, e.UpdatedAt, e.FinishedAt = fromMilli(started), fromMilli(updated), fromMilli(finished)
	e.Continued = continued != 0
	e.RunTime = time.Duration(run) * time.Millisecond
	return &e, nil
}

func collect(rows *sql.Rows) ([]*IndexEntry, error) {
	defer closeRows(rows)
	var out []*IndexEntry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("read scan index: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read scan index: %w", err)
	}
	return out, nil
}

// NewScanID returns a random 12-character hex id.
func NewScanID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("make scan id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func unixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMilli(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		log.Warnf("state: close rows: %v", err)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}

func escapeLike(s string) string {
	r := ""
	for _, c := range s {
		if c == '%' || c == '_' || c == '\\' {
			r += `\`
		}
		r += string(c)
	}
	return r
}

package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/safedep/dry/localdb"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// scanMigrations is the schema of one scan file. The scan file is not a
// public format: the report stream is the contract. Rows hold the record
// JSON next to the columns that queries filter on.
var scanMigrations = []string{
	`CREATE TABLE vet_scan_meta (
		key   TEXT PRIMARY KEY,
		value BLOB NOT NULL
	)`,
	`CREATE TABLE vet_scan_stages (
		name        TEXT PRIMARY KEY,
		status      TEXT NOT NULL,
		started_at  INTEGER NOT NULL DEFAULT 0,
		finished_at INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE vet_scan_artifacts (
		key        TEXT PRIMARY KEY,
		kind       TEXT NOT NULL,
		path       TEXT NOT NULL,
		size       INTEGER NOT NULL DEFAULT 0,
		mtime      INTEGER NOT NULL DEFAULT 0,
		status     TEXT NOT NULL,
		error      TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE vet_scan_manifests (
		id           TEXT PRIMARY KEY,
		seq          INTEGER NOT NULL,
		artifact_key TEXT NOT NULL,
		path         TEXT NOT NULL,
		ecosystem    TEXT NOT NULL,
		kind         TEXT NOT NULL,
		evaluated    INTEGER NOT NULL DEFAULT 0,
		data         BLOB NOT NULL
	)`,
	`CREATE TABLE vet_scan_packages (
		purl      TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		name      TEXT NOT NULL,
		version   TEXT NOT NULL,
		insight   BLOB,
		malware   BLOB,
		usage     BLOB
	)`,
	`CREATE TABLE vet_scan_manifest_packages (
		manifest_id TEXT NOT NULL,
		purl        TEXT NOT NULL,
		seq         INTEGER NOT NULL,
		change      TEXT NOT NULL,
		data        BLOB NOT NULL,
		PRIMARY KEY (manifest_id, purl)
	)`,
	`CREATE INDEX vet_scan_manifest_packages_purl ON vet_scan_manifest_packages (purl)`,
	`CREATE TABLE vet_scan_edges (
		manifest_id TEXT NOT NULL,
		parent      TEXT NOT NULL,
		child       TEXT NOT NULL,
		PRIMARY KEY (manifest_id, parent, child)
	)`,
	`CREATE INDEX vet_scan_edges_child ON vet_scan_edges (child)`,
	`CREATE TABLE vet_scan_roots (
		manifest_id TEXT NOT NULL,
		purl        TEXT NOT NULL,
		PRIMARY KEY (manifest_id, purl)
	)`,
	`CREATE TABLE vet_scan_enrichments (
		purl       TEXT NOT NULL,
		enricher   TEXT NOT NULL,
		status     TEXT NOT NULL,
		fetched_at INTEGER NOT NULL,
		PRIMARY KEY (purl, enricher)
	)`,
	`CREATE TABLE vet_scan_findings (
		id            TEXT PRIMARY KEY,
		control_id    TEXT NOT NULL,
		manifest_id   TEXT NOT NULL,
		severity_rank INTEGER NOT NULL,
		suppressed    INTEGER NOT NULL,
		data          BLOB NOT NULL
	)`,
	`CREATE TABLE vet_scan_inventory (
		seq  INTEGER PRIMARY KEY,
		data BLOB NOT NULL
	)`,
	`CREATE TABLE vet_scan_diagnostics (
		seq       INTEGER PRIMARY KEY,
		code      TEXT NOT NULL,
		component TEXT NOT NULL,
		data      BLOB NOT NULL
	)`,
}

const (
	metaHeader  = "header"
	metaOptions = "options"
	metaTrailer = "trailer"
)

// Artifact statuses in the scan file.
const (
	ArtifactPending   = "pending"
	ArtifactExtracted = "extracted"
	ArtifactFailed    = "failed"
)

// Scan is one scan file. It implements plugin.State and plugin.Report.
type Scan struct {
	id   string
	mgr  localdb.FileManager
	db   *sql.DB
	lock *scanLock

	mu      sync.Mutex
	header  *report.Header
	trailer *report.Trailer
}

func openScanFile(ctx context.Context, dir, id string) (*Scan, error) {
	mgr, err := openFile(dir, id+".db")
	if err != nil {
		return nil, err
	}
	st, err := mgr.Store(ctx, localdb.Descriptor{Name: "vet_scan", Migrations: scanMigrations})
	if err != nil {
		return nil, fmt.Errorf("open scan file %s: %w", id, err)
	}
	s := &Scan{id: id, mgr: mgr, db: st.DB()}
	if err := s.loadMeta(ctx); err != nil {
		return nil, errors.Join(err, mgr.Close())
	}
	return s, nil
}

// ID returns the scan id.
func (s *Scan) ID() string { return s.id }

// Path returns the path of the scan file.
func (s *Scan) Path() string { return s.mgr.Path() }

// Size returns the size of the scan file in bytes.
func (s *Scan) Size() (int64, error) { return s.mgr.Size() }

// Close flushes and closes the scan file.
// Close closes the scan file and releases the lock of a running scan.
func (s *Scan) Close() error {
	err := errors.Join(s.mgr.Close(), s.lock.release())
	s.lock = nil
	return err
}

func (s *Scan) setMeta(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO vet_scan_meta (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, b)
	if err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}

func (s *Scan) getMeta(ctx context.Context, key string, v any) (bool, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM vet_scan_meta WHERE key = ?`, key).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", key, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("decode %s: %w", key, err)
	}
	return true, nil
}

// SetHeader writes the report header.
func (s *Scan) SetHeader(ctx context.Context, h *report.Header) error {
	if err := s.setMeta(ctx, metaHeader, h); err != nil {
		return err
	}
	s.mu.Lock()
	s.header = h
	s.mu.Unlock()
	return nil
}

// SetOptions writes the scan options that the options hash covers.
func (s *Scan) SetOptions(ctx context.Context, opts any) error {
	return s.setMeta(ctx, metaOptions, opts)
}

// Options reads the scan options into v.
func (s *Scan) Options(ctx context.Context, v any) (bool, error) {
	return s.getMeta(ctx, metaOptions, v)
}

// SetTrailer writes the report trailer. A scan with a trailer is complete.
func (s *Scan) SetTrailer(ctx context.Context, t *report.Trailer) error {
	if err := s.setMeta(ctx, metaTrailer, t); err != nil {
		return err
	}
	s.mu.Lock()
	s.trailer = t
	s.mu.Unlock()
	return nil
}

// SetStage records the status of a pipeline stage.
func (s *Scan) SetStage(ctx context.Context, name, status string) error {
	now := time.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `INSERT INTO vet_scan_stages (name, status, started_at) VALUES (?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET status = excluded.status,
		finished_at = CASE WHEN excluded.status IN ('done', 'failed') THEN ? ELSE finished_at END`,
		name, status, now, now)
	if err != nil {
		return fmt.Errorf("write stage %s: %w", name, err)
	}
	return nil
}

// Stage returns the status of a stage, or "".
func (s *Scan) Stage(ctx context.Context, name string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM vet_scan_stages WHERE name = ?`, name).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read stage %s: %w", name, err)
	}
	return status, nil
}

// ArtifactRecord is one input file or target of a scan.
type ArtifactRecord struct {
	Key    string
	Kind   string
	Path   string
	Size   int64
	MTime  time.Time
	Status string
	Error  string
}

// PutArtifact writes an artifact row.
func (s *Scan) PutArtifact(ctx context.Context, a ArtifactRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vet_scan_artifacts (key, kind, path, size, mtime, status, error)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET kind = excluded.kind, path = excluded.path, size = excluded.size,
		mtime = excluded.mtime, status = excluded.status, error = excluded.error`,
		a.Key, a.Kind, a.Path, a.Size, unixMilli(a.MTime), a.Status, a.Error)
	if err != nil {
		return fmt.Errorf("write artifact %s: %w", a.Key, err)
	}
	return nil
}

// Artifact returns the artifact row of a key, or nil.
func (s *Scan) Artifact(ctx context.Context, key string) (*ArtifactRecord, error) {
	var a ArtifactRecord
	var mtime int64
	err := s.db.QueryRowContext(ctx, `SELECT key, kind, path, size, mtime, status, error FROM vet_scan_artifacts WHERE key = ?`, key).
		Scan(&a.Key, &a.Kind, &a.Path, &a.Size, &mtime, &a.Status, &a.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read artifact %s: %w", key, err)
	}
	a.MTime = fromMilli(mtime)
	return &a, nil
}

// manifestData is the JSON of a manifest row.
type manifestData struct {
	Manifest *model.Manifest `json:"manifest"`
}

// packageData is the JSON of a manifest package row: the package without
// its data fields, which the packages table holds once for each PURL.
type packageData struct {
	model.Package
}

// AddManifest writes a manifest with its packages and graph, and marks its
// artifact extracted, in one transaction. A stopped scan then never holds
// half a manifest.
func (s *Scan) AddManifest(ctx context.Context, artifactKey string, m *model.Manifest) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := addManifestTx(ctx, tx, artifactKey, m); err != nil {
			return err
		}
		if artifactKey == "" {
			return nil
		}
		_, err := tx.ExecContext(ctx, `UPDATE vet_scan_artifacts SET status = ? WHERE key = ?`, ArtifactExtracted, artifactKey)
		return err
	})
}

func addManifestTx(ctx context.Context, tx *sql.Tx, artifactKey string, m *model.Manifest) error {
	var seq int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM vet_scan_manifests`).Scan(&seq); err != nil {
		return err
	}
	md, err := json.Marshal(manifestData{Manifest: m})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vet_scan_manifests (id, seq, artifact_key, path, ecosystem, kind, data)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET artifact_key = excluded.artifact_key, path = excluded.path,
		ecosystem = excluded.ecosystem, kind = excluded.kind, data = excluded.data`,
		m.ID, seq, artifactKey, m.Path, string(m.Ecosystem), string(m.Kind), md); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vet_scan_manifest_packages WHERE manifest_id = ?`, m.ID); err != nil {
		return err
	}
	for i, p := range m.Packages {
		purl := p.ID.PURL()
		if _, err := tx.ExecContext(ctx, `INSERT INTO vet_scan_packages (purl, ecosystem, name, version)
			VALUES (?, ?, ?, ?) ON CONFLICT (purl) DO NOTHING`,
			purl, string(p.ID.Ecosystem), p.ID.QualifiedName(), p.ID.Version); err != nil {
			return err
		}
		bare := *p
		bare.Insight, bare.Malware, bare.Usage = nil, nil, nil
		pd, err := json.Marshal(packageData{Package: bare})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vet_scan_manifest_packages (manifest_id, purl, seq, change, data)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (manifest_id, purl) DO UPDATE SET data = excluded.data, change = excluded.change`,
			m.ID, purl, i, string(p.Change), pd); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vet_scan_edges WHERE manifest_id = ?`, m.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vet_scan_roots WHERE manifest_id = ?`, m.ID); err != nil {
		return err
	}
	if m.Graph != nil {
		for _, r := range m.Graph.Roots() {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vet_scan_roots (manifest_id, purl) VALUES (?, ?)`,
				m.ID, r.PURL()); err != nil {
				return err
			}
		}
		var edgeErr error
		m.Graph.Edges(func(parent, child model.PackageID) {
			if edgeErr != nil {
				return
			}
			_, edgeErr = tx.ExecContext(ctx, `INSERT OR IGNORE INTO vet_scan_edges (manifest_id, parent, child) VALUES (?, ?, ?)`,
				m.ID, parent.PURL(), child.PURL())
		})
		if edgeErr != nil {
			return edgeErr
		}
	}
	return nil
}

// Enrichment statuses.
const (
	EnrichmentOK       = "ok"
	EnrichmentNotFound = "not_found"
	EnrichmentFailed   = "failed"
)

// ArtifactStale marks an artifact of a continued scan that the current run
// has not seen yet.
const ArtifactStale = "stale"

// CommitArtifact writes the manifests of one artifact and marks it
// extracted, in one transaction. It first deletes the manifests that an
// earlier run read from the artifact.
func (s *Scan) CommitArtifact(ctx context.Context, a ArtifactRecord, ms []*model.Manifest) error {
	a.Status = ArtifactExtracted
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := deleteManifestsTx(ctx, tx, `artifact_key = ?`, a.Key); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vet_scan_artifacts (key, kind, path, size, mtime, status, error)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET kind = excluded.kind, path = excluded.path, size = excluded.size,
			mtime = excluded.mtime, status = excluded.status, error = excluded.error`,
			a.Key, a.Kind, a.Path, a.Size, unixMilli(a.MTime), a.Status, a.Error); err != nil {
			return fmt.Errorf("write artifact %s: %w", a.Key, err)
		}
		for _, m := range ms {
			if err := addManifestTx(ctx, tx, a.Key, m); err != nil {
				return err
			}
		}
		return nil
	})
}

// deleteManifestsTx deletes the manifests that match a condition, with
// their packages, edges, roots and findings.
func deleteManifestsTx(ctx context.Context, tx *sql.Tx, where string, args ...any) error {
	sub := `SELECT id FROM vet_scan_manifests WHERE ` + where
	for _, table := range []string{"vet_scan_manifest_packages", "vet_scan_edges", "vet_scan_roots", "vet_scan_findings"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE manifest_id IN (`+sub+`)`, args...); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM vet_scan_manifests WHERE `+where, args...)
	return err
}

// MarkArtifactsStale marks each extracted artifact stale. A continued scan
// calls it before it walks the target again.
func (s *Scan) MarkArtifactsStale(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vet_scan_artifacts SET status = ? WHERE status = ?`, ArtifactStale, ArtifactExtracted)
	return err
}

// ReviveArtifact marks a stale artifact extracted again, when the file has
// not changed.
func (s *Scan) ReviveArtifact(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vet_scan_artifacts SET status = ? WHERE key = ?`, ArtifactExtracted, key)
	return err
}

// DropStaleArtifacts deletes the artifacts that the run did not see, with
// their manifests. It returns how many it deleted.
func (s *Scan) DropStaleArtifacts(ctx context.Context) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := deleteManifestsTx(ctx, tx, `artifact_key IN (SELECT key FROM vet_scan_artifacts WHERE status = ?)`, ArtifactStale); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM vet_scan_artifacts WHERE status = ?`, ArtifactStale)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// ClearFindings deletes every finding and marks each manifest not
// evaluated. A run evaluates the controls again, because the policy can
// change between runs.
func (s *Scan) ClearFindings(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM vet_scan_findings`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE vet_scan_manifests SET evaluated = 0`)
		return err
	})
}

// Counts returns the number of distinct packages and of findings.
func (s *Scan) Counts(ctx context.Context) (packages, findings int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(DISTINCT purl) FROM vet_scan_manifest_packages),
		(SELECT COUNT(*) FROM vet_scan_findings)`).Scan(&packages, &findings)
	return packages, findings, err
}

// EnrichmentResult is the data that one enricher set on one package.
type EnrichmentResult struct {
	Package  *model.Package
	Enricher string
	// Status is EnrichmentOK, EnrichmentNotFound or EnrichmentFailed.
	Status string
}

// SaveEnrichments writes the data fields of a batch and marks each package
// enriched by the enricher, in one transaction.
func (s *Scan) SaveEnrichments(ctx context.Context, results []EnrichmentResult) error {
	if len(results) == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, r := range results {
			purl := r.Package.ID.PURL()
			insight, err := marshalOrNil(r.Package.Insight)
			if err != nil {
				return err
			}
			malware, err := marshalOrNil(r.Package.Malware)
			if err != nil {
				return err
			}
			usage, err := marshalOrNil(r.Package.Usage)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE vet_scan_packages SET
				insight = COALESCE(?, insight), malware = COALESCE(?, malware), usage = COALESCE(?, usage)
				WHERE purl = ?`, insight, malware, usage, purl); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO vet_scan_enrichments (purl, enricher, status, fetched_at)
				VALUES (?, ?, ?, ?) ON CONFLICT (purl, enricher) DO UPDATE SET status = excluded.status,
				fetched_at = excluded.fetched_at`, purl, r.Enricher, r.Status, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// AddFindings writes the findings of one manifest and marks the manifest
// evaluated, in one transaction.
func (s *Scan) AddFindings(ctx context.Context, manifestID string, findings []finding.Finding) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for i := range findings {
			if err := insertFinding(ctx, tx, manifestID, &findings[i]); err != nil {
				return err
			}
		}
		if manifestID != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE vet_scan_manifests SET evaluated = 1 WHERE id = ?`, manifestID); err != nil {
				return err
			}
		}
		return nil
	})
}

// ReplaceFinding writes a finding again, for example after a policy
// suppression.
func (s *Scan) ReplaceFinding(ctx context.Context, manifestID string, f *finding.Finding) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return insertFinding(ctx, tx, manifestID, f) })
}

func insertFinding(ctx context.Context, tx *sql.Tx, manifestID string, f *finding.Finding) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO vet_scan_findings (id, control_id, manifest_id, severity_rank, suppressed, data)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET severity_rank = excluded.severity_rank, suppressed = excluded.suppressed,
		data = excluded.data`,
		f.ID, f.ControlID, manifestID, f.Severity.Rank(), boolInt(f.Suppressed()), b)
	return err
}

// AddInventory writes an inventory item.
func (s *Scan) AddInventory(ctx context.Context, item *report.InventoryItem) error {
	b, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vet_scan_inventory (data) VALUES (?)`, b); err != nil {
		return fmt.Errorf("write inventory item: %w", err)
	}
	return nil
}

// AddDiagnostic writes a diagnostic.
func (s *Scan) AddDiagnostic(ctx context.Context, d *report.Diagnostic) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vet_scan_diagnostics (code, component, data) VALUES (?, ?, ?)`,
		d.Code, d.Component, b); err != nil {
		return fmt.Errorf("write diagnostic: %w", err)
	}
	return nil
}

func (s *Scan) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("scan file: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(fmt.Errorf("scan file: %w", err), rbErr)
		}
		return fmt.Errorf("scan file: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("scan file: commit: %w", err)
	}
	return nil
}

func marshalOrNil(v any) ([]byte, error) {
	switch x := v.(type) {
	case *model.Insight:
		if x == nil {
			return nil, nil
		}
	case *model.MalwareAnalysis:
		if x == nil {
			return nil, nil
		}
	case *model.Usage:
		if x == nil {
			return nil, nil
		}
	}
	return json.Marshal(v)
}

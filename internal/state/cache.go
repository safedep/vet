package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/model"
)

// cacheMigrations is the schema of cache.db. The cache is safe to delete,
// so it lives in its own file and not in the index.
var cacheMigrations = []string{
	`CREATE TABLE vet_cache_enrichments (
		purl             TEXT NOT NULL,
		enricher         TEXT NOT NULL,
		enricher_version TEXT NOT NULL,
		status           TEXT NOT NULL,
		data             BLOB NOT NULL,
		fetched_at       INTEGER NOT NULL,
		expires_at       INTEGER NOT NULL,
		PRIMARY KEY (purl, enricher, enricher_version)
	)`,
	`CREATE INDEX vet_cache_enrichments_expires ON vet_cache_enrichments (expires_at)`,
}

// cachedData holds the package fields that an enricher sets.
type cachedData struct {
	Insight *model.Insight         `json:"insight,omitempty"`
	Malware *model.MalwareAnalysis `json:"malware,omitempty"`
	Usage   *model.Usage           `json:"usage,omitempty"`
}

// Cache is the enrichment cache in cache.db. Several vet processes can
// share it.
type Cache struct {
	mgr localdb.FileManager
	db  *sql.DB
	now func() time.Time
}

// OpenCache opens cache.db in the cache directory.
func OpenCache(ctx context.Context, dir string) (*Cache, error) {
	if err := appdir.Ensure(dir); err != nil {
		return nil, err
	}
	mgr := openFile(dir, "cache.db")
	st, err := mgr.Store(ctx, localdb.Descriptor{Name: "vet_cache", Migrations: cacheMigrations})
	if err != nil {
		return nil, fmt.Errorf("open the enrichment cache: %w", err)
	}
	return &Cache{mgr: mgr, db: st.DB(), now: time.Now}, nil
}

// Close closes the cache.
func (c *Cache) Close() error { return c.mgr.Close() }

// Path returns the path of cache.db.
func (c *Cache) Path() string { return c.mgr.Path() }

// Lookup sets the cached data of an enricher on each package that has a
// live entry. It returns the results of the hits and the packages that
// the enricher must still enrich.
func (c *Cache) Lookup(ctx context.Context, enricher, version string, pkgs []*model.Package) ([]EnrichmentResult, []*model.Package, error) {
	stmt, err := c.db.PrepareContext(ctx, `SELECT status, data FROM vet_cache_enrichments
		WHERE purl = ? AND enricher = ? AND enricher_version = ? AND expires_at > ?`)
	if err != nil {
		return nil, nil, fmt.Errorf("read the enrichment cache: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Warnf("close the cache statement: %v", err)
		}
	}()

	now := c.now().UnixMilli()
	var hits []EnrichmentResult
	var misses []*model.Package
	for _, p := range pkgs {
		var status string
		var data []byte
		err := stmt.QueryRowContext(ctx, p.ID.PURL(), enricher, version, now).Scan(&status, &data)
		if errors.Is(err, sql.ErrNoRows) {
			misses = append(misses, p)
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read the enrichment cache: %w", err)
		}
		var cd cachedData
		if err := json.Unmarshal(data, &cd); err != nil {
			return nil, nil, fmt.Errorf("decode the enrichment cache: %w", err)
		}
		if cd.Insight != nil {
			p.Insight = cd.Insight
		}
		if cd.Malware != nil {
			p.Malware = cd.Malware
		}
		if cd.Usage != nil {
			p.Usage = cd.Usage
		}
		hits = append(hits, EnrichmentResult{Package: p, Enricher: enricher, Status: status})
	}
	return hits, misses, nil
}

// Put writes the results of one enricher version. A failed result is not
// cached, so the next run asks again.
func (c *Cache) Put(ctx context.Context, version string, ttl time.Duration, results []EnrichmentResult) error {
	if len(results) == 0 || ttl <= 0 {
		return nil
	}
	now := c.now()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Status == EnrichmentFailed {
			continue
		}
		data, err := json.Marshal(cachedData{Insight: r.Package.Insight, Malware: r.Package.Malware, Usage: r.Package.Usage})
		if err != nil {
			return errors.Join(err, tx.Rollback())
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vet_cache_enrichments
			(purl, enricher, enricher_version, status, data, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (purl, enricher, enricher_version) DO UPDATE SET status = excluded.status,
			data = excluded.data, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`,
			r.Package.ID.PURL(), r.Enricher, version, r.Status, data, now.UnixMilli(), now.Add(ttl).UnixMilli()); err != nil {
			return errors.Join(fmt.Errorf("write the enrichment cache: %w", err), tx.Rollback())
		}
	}
	return tx.Commit()
}

// Prune deletes the expired entries and returns how many it deleted.
func (c *Cache) Prune(ctx context.Context) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM vet_cache_enrichments WHERE expires_at <= ?`, c.now().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("prune the enrichment cache: %w", err)
	}
	return res.RowsAffected()
}

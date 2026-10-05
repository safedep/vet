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
	// The cache keys a package by its PackageKey, the canonical form under
	// the rule version, and no longer by its PURL. The old rows hold the
	// PURL spelling, so the migration drops them.
	`DROP TABLE vet_cache_enrichments`,
	`CREATE TABLE vet_cache_package_enrichments (
		pkey             TEXT NOT NULL,
		enricher         TEXT NOT NULL,
		enricher_version TEXT NOT NULL,
		status           TEXT NOT NULL,
		data             BLOB NOT NULL,
		fetched_at       INTEGER NOT NULL,
		expires_at       INTEGER NOT NULL,
		PRIMARY KEY (pkey, enricher, enricher_version)
	)`,
	`CREATE INDEX vet_cache_package_enrichments_expires ON vet_cache_package_enrichments (expires_at)`,
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
	mgr, err := openFile(dir, "cache.db")
	if err != nil {
		return nil, err
	}
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
	stmt, err := c.db.PrepareContext(ctx, `SELECT status, data FROM vet_cache_package_enrichments
		WHERE pkey = ? AND enricher = ? AND enricher_version = ? AND expires_at > ?`)
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
		err := stmt.QueryRowContext(ctx, string(p.ID.Key()), enricher, version, now).Scan(&status, &data)
		if errors.Is(err, sql.ErrNoRows) {
			misses = append(misses, p)
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read the enrichment cache: %w", err)
		}
		var cached model.Enrichment
		if err := json.Unmarshal(data, &cached); err != nil {
			return nil, nil, fmt.Errorf("decode the enrichment cache: %w", err)
		}
		p.Enrichment = p.Enrichment.Merge(cached)
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
		data, err := json.Marshal(r.Package.Enrichment)
		if err != nil {
			return errors.Join(err, tx.Rollback())
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vet_cache_package_enrichments
			(pkey, enricher, enricher_version, status, data, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (pkey, enricher, enricher_version) DO UPDATE SET status = excluded.status,
			data = excluded.data, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`,
			string(r.Package.ID.Key()), r.Enricher, version, r.Status, data, now.UnixMilli(), now.Add(ttl).UnixMilli()); err != nil {
			return errors.Join(fmt.Errorf("write the enrichment cache: %w", err), tx.Rollback())
		}
	}
	return tx.Commit()
}

// Prune deletes the expired entries and returns how many it deleted.
func (c *Cache) Prune(ctx context.Context) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM vet_cache_package_enrichments WHERE expires_at <= ?`, c.now().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("prune the enrichment cache: %w", err)
	}
	return res.RowsAffected()
}

// CacheStats counts the entries of the cache.
type CacheStats struct {
	Entries int
	Oldest  time.Time
}

// Stats returns the number of entries and the time of the oldest one.
func (c *Cache) Stats(ctx context.Context) (CacheStats, error) {
	var st CacheStats
	var oldest sql.NullInt64
	err := c.db.QueryRowContext(ctx, `SELECT COUNT(*), MIN(fetched_at) FROM vet_cache_package_enrichments`).Scan(&st.Entries, &oldest)
	if err != nil {
		return st, fmt.Errorf("count the enrichment cache: %w", err)
	}
	if oldest.Valid {
		st.Oldest = time.UnixMilli(oldest.Int64).UTC()
	}
	return st, nil
}

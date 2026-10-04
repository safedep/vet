package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"iter"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

var _ plugin.State = (*Scan)(nil)

// Manifests yields each manifest with its packages and graph, in the order
// that the scan extracted them.
func (s *Scan) Manifests(ctx context.Context) iter.Seq2[*model.Manifest, error] {
	return func(yield func(*model.Manifest, error) bool) {
		ids, err := s.manifestIDs(ctx)
		if err != nil {
			yield(nil, err)
			return
		}
		for _, id := range ids {
			m, err := s.Manifest(ctx, id)
			if !yield(m, err) || err != nil {
				return
			}
		}
	}
}

func (s *Scan) manifestIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM vet_scan_manifests ORDER BY seq, id`)
	if err != nil {
		return nil, fmt.Errorf("list manifests: %w", err)
	}
	defer closeRows(rows)
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Manifest loads one manifest with its packages and graph.
func (s *Scan) Manifest(ctx context.Context, id string) (*model.Manifest, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT data FROM vet_scan_manifests WHERE id = ?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("manifest %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", id, err)
	}
	var md manifestData
	if err := json.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("decode manifest %s: %w", id, err)
	}
	m := md.Manifest

	rows, err := s.db.QueryContext(ctx, `SELECT mp.data, p.insight, p.malware, p.usage
		FROM vet_scan_manifest_packages mp JOIN vet_scan_packages p ON p.purl = mp.purl
		WHERE mp.manifest_id = ? ORDER BY mp.seq`, id)
	if err != nil {
		return nil, fmt.Errorf("read packages of %s: %w", id, err)
	}
	m.Packages = nil
	for p, err := range decodePackages(rows) {
		if err != nil {
			return nil, err
		}
		m.Packages = append(m.Packages, p)
	}
	if err := s.attachPrior(ctx, m.Packages); err != nil {
		return nil, err
	}

	g, err := s.graph(ctx, id)
	if err != nil {
		return nil, err
	}
	m.Graph = g
	return m, nil
}

func (s *Scan) graph(ctx context.Context, manifestID string) (*model.Graph, error) {
	g := model.NewGraph()
	found := false
	roots, err := s.db.QueryContext(ctx, `SELECT purl FROM vet_scan_roots WHERE manifest_id = ? ORDER BY purl`, manifestID)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	for roots.Next() {
		var purl string
		if err := roots.Scan(&purl); err != nil {
			closeRows(roots)
			return nil, err
		}
		id, err := model.ParsePURL(purl)
		if err != nil {
			closeRows(roots)
			return nil, err
		}
		g.AddRoot(id)
		found = true
	}
	closeRows(roots)

	edges, err := s.db.QueryContext(ctx, `SELECT parent, child FROM vet_scan_edges WHERE manifest_id = ? ORDER BY parent, child`, manifestID)
	if err != nil {
		return nil, fmt.Errorf("read edges: %w", err)
	}
	defer closeRows(edges)
	for edges.Next() {
		var parent, child string
		if err := edges.Scan(&parent, &child); err != nil {
			return nil, err
		}
		pid, err := model.ParsePURL(parent)
		if err != nil {
			return nil, err
		}
		cid, err := model.ParsePURL(child)
		if err != nil {
			return nil, err
		}
		g.AddEdge(pid, cid)
		found = true
	}
	if err := edges.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return g, nil
}

func decodePackages(rows *sql.Rows) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		defer closeRows(rows)
		for rows.Next() {
			var data, insight, malware, usage []byte
			if err := rows.Scan(&data, &insight, &malware, &usage); err != nil {
				yield(nil, err)
				return
			}
			var pd packageData
			if err := json.Unmarshal(data, &pd); err != nil {
				yield(nil, fmt.Errorf("decode package: %w", err))
				return
			}
			p := pd.Package
			if err := unmarshalIf(insight, &p.Insight); err != nil {
				yield(nil, err)
				return
			}
			if err := unmarshalIf(malware, &p.Malware); err != nil {
				yield(nil, err)
				return
			}
			if err := unmarshalIf(usage, &p.Usage); err != nil {
				yield(nil, err)
				return
			}
			if !yield(&p, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, err)
		}
	}
}

func unmarshalIf[T any](b []byte, dst **T) error {
	if len(b) == 0 {
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("decode package data: %w", err)
	}
	*dst = &v
	return nil
}

// Packages yields the packages that match the query. A package in two
// manifests comes once for each manifest, unless the query names one.
func (s *Scan) Packages(ctx context.Context, q plugin.PackageQuery) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		sqlq := `SELECT mp.data, p.insight, p.malware, p.usage
			FROM vet_scan_manifest_packages mp JOIN vet_scan_packages p ON p.purl = mp.purl
			JOIN vet_scan_manifests m ON m.id = mp.manifest_id WHERE 1 = 1`
		var args []any
		if q.ManifestID != "" {
			sqlq += ` AND mp.manifest_id = ?`
			args = append(args, q.ManifestID)
		}
		if q.Ecosystem != "" {
			sqlq += ` AND p.ecosystem = ?`
			args = append(args, string(q.Ecosystem))
		}
		if q.ChangedOnly {
			sqlq += ` AND mp.change IN ('ADDED', 'UPGRADED', 'DOWNGRADED', 'MODIFIED')`
		}
		sqlq += ` ORDER BY m.seq, mp.seq`
		rows, err := s.db.QueryContext(ctx, sqlq, args...)
		if err != nil {
			yield(nil, fmt.Errorf("query packages: %w", err))
			return
		}
		for p, err := range decodePackages(rows) {
			if !yield(p, err) || err != nil {
				return
			}
		}
	}
}

// Package returns the package with the identity, from the first manifest
// that declares it.
func (s *Scan) Package(ctx context.Context, id model.PackageID) (*model.Package, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mp.data, p.insight, p.malware, p.usage
		FROM vet_scan_manifest_packages mp JOIN vet_scan_packages p ON p.purl = mp.purl
		JOIN vet_scan_manifests m ON m.id = mp.manifest_id
		WHERE mp.purl = ? ORDER BY m.seq LIMIT 1`, id.PURL())
	if err != nil {
		return nil, fmt.Errorf("query package %s: %w", id, err)
	}
	for p, err := range decodePackages(rows) {
		return p, err
	}
	return nil, fmt.Errorf("package %s: %w", id, ErrNotFound)
}

// Dependents yields the packages that depend on the identity in any manifest.
func (s *Scan) Dependents(ctx context.Context, id model.PackageID) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		rows, err := s.db.QueryContext(ctx, `SELECT mp.data, p.insight, p.malware, p.usage
			FROM vet_scan_edges e
			JOIN vet_scan_manifest_packages mp ON mp.manifest_id = e.manifest_id AND mp.purl = e.parent
			JOIN vet_scan_packages p ON p.purl = mp.purl
			WHERE e.child = ? ORDER BY e.manifest_id, e.parent`, id.PURL())
		if err != nil {
			yield(nil, fmt.Errorf("query dependents of %s: %w", id, err))
			return
		}
		for p, err := range decodePackages(rows) {
			if !yield(p, err) || err != nil {
				return
			}
		}
	}
}

// Findings yields the findings that match the query, the most severe first.
func (s *Scan) Findings(ctx context.Context, q plugin.FindingQuery) iter.Seq2[*finding.Finding, error] {
	return func(yield func(*finding.Finding, error) bool) {
		sqlq := `SELECT data FROM vet_scan_findings WHERE 1 = 1`
		var args []any
		if q.ControlID != "" {
			sqlq += ` AND control_id = ?`
			args = append(args, q.ControlID)
		}
		if q.MinSeverity != "" {
			sqlq += ` AND severity_rank >= ?`
			args = append(args, q.MinSeverity.Rank())
		}
		if !q.IncludeSuppressed {
			sqlq += ` AND suppressed = 0`
		}
		sqlq += ` ORDER BY severity_rank DESC, control_id, id`
		rows, err := s.db.QueryContext(ctx, sqlq, args...)
		if err != nil {
			yield(nil, fmt.Errorf("query findings: %w", err))
			return
		}
		defer closeRows(rows)
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				yield(nil, err)
				return
			}
			var f finding.Finding
			if err := json.Unmarshal(data, &f); err != nil {
				yield(nil, fmt.Errorf("decode finding: %w", err))
				return
			}
			if !yield(&f, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, err)
		}
	}
}

// FindingManifest returns the manifest id that a finding belongs to.
func (s *Scan) FindingManifest(ctx context.Context, findingID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT manifest_id FROM vet_scan_findings WHERE id = ?`, findingID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// UnevaluatedManifests returns the ids of the manifests that no control run
// has finished, in extraction order.
func (s *Scan) UnevaluatedManifests(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM vet_scan_manifests WHERE evaluated = 0 ORDER BY seq, id`)
	if err != nil {
		return nil, fmt.Errorf("list manifests: %w", err)
	}
	defer closeRows(rows)
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// PackagesLacking yields the distinct packages that an enricher has not
// enriched yet, in PURL order.
func (s *Scan) PackagesLacking(ctx context.Context, enricher string) iter.Seq2[*model.Package, error] {
	return func(yield func(*model.Package, error) bool) {
		rows, err := s.db.QueryContext(ctx, `SELECT mp.data, p.insight, p.malware, p.usage
			FROM vet_scan_packages p
			JOIN vet_scan_manifest_packages mp ON mp.purl = p.purl
			  AND mp.manifest_id = (SELECT manifest_id FROM vet_scan_manifest_packages WHERE purl = p.purl ORDER BY manifest_id LIMIT 1)
			WHERE NOT EXISTS (SELECT 1 FROM vet_scan_enrichments e WHERE e.purl = p.purl AND e.enricher = ?)
			ORDER BY p.purl`, enricher)
		if err != nil {
			yield(nil, fmt.Errorf("query packages to enrich: %w", err))
			return
		}
		for p, err := range decodePackages(rows) {
			if !yield(p, err) || err != nil {
				return
			}
		}
	}
}

// EnrichQuery selects a page of packages for an enricher.
type EnrichQuery struct {
	Enricher string
	// After is the PURL cursor: the page starts after it.
	After string
	Limit int
	// Introduced keeps the packages that pull request mode marks added,
	// upgraded or downgraded.
	Introduced bool
}

// PackagesToEnrich returns up to q.Limit distinct packages, in PURL order and
// after q.After, that the enricher has no "ok" or "not_found" result for. A
// failed result comes back, so a continued scan tries it again. The PURL
// cursor lets a run page through the packages while it writes results.
func (s *Scan) PackagesToEnrich(ctx context.Context, q EnrichQuery) ([]*model.Package, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mp.data, p.insight, p.malware, p.usage
		FROM vet_scan_packages p
		JOIN vet_scan_manifest_packages mp ON mp.purl = p.purl
		  AND mp.manifest_id = (SELECT manifest_id FROM vet_scan_manifest_packages WHERE purl = p.purl ORDER BY manifest_id LIMIT 1)
		WHERE p.purl > ? AND NOT `+enriched+introducedFilter(q.Introduced)+`
		ORDER BY p.purl LIMIT ?`, q.After, q.Enricher, EnrichmentOK, EnrichmentNotFound, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("query packages to enrich: %w", err)
	}
	var out []*model.Package
	for p, err := range decodePackages(rows) {
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// enriched holds for a package that the enricher has an "ok" or a
// "not_found" result for. Its arguments are the enricher and the two
// statuses.
const enriched = `EXISTS (SELECT 1 FROM vet_scan_enrichments e
		    WHERE e.purl = p.purl AND e.enricher = ? AND e.status IN (?, ?))`

func introducedFilter(introduced bool) string {
	if !introduced {
		return ""
	}
	return ` AND EXISTS (SELECT 1 FROM vet_scan_manifest_packages c
		    WHERE c.purl = p.purl AND c.change IN ('ADDED', 'UPGRADED', 'DOWNGRADED', 'MODIFIED'))`
}

// EnrichCounts returns the number of packages that the enricher of q
// checks, and the number of them that PackagesToEnrich still returns. It
// ignores q.After and q.Limit.
func (s *Scan) EnrichCounts(ctx context.Context, q EnrichQuery) (all, todo int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(NOT `+enriched+`), 0)
		FROM vet_scan_packages p
		WHERE EXISTS (SELECT 1 FROM vet_scan_manifest_packages mp WHERE mp.purl = p.purl)`+introducedFilter(q.Introduced),
		q.Enricher, EnrichmentOK, EnrichmentNotFound).Scan(&all, &todo)
	if err != nil {
		return 0, 0, fmt.Errorf("count packages to enrich: %w", err)
	}
	return all, todo, nil
}

// PriorID returns the identity of the previous version of an upgraded or a
// downgraded package.
func PriorID(p *model.Package) (model.PackageID, bool) {
	if p.PreviousVersion == "" || (p.Change != model.ChangeUpgraded && p.Change != model.ChangeDowngraded) {
		return model.PackageID{}, false
	}
	id := p.ID
	id.Version = p.PreviousVersion
	return id, true
}

// PriorToEnrich returns the previous versions of the upgraded and the
// downgraded packages that have no prior data yet.
func (s *Scan) PriorToEnrich(ctx context.Context) ([]*model.Package, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM vet_scan_manifest_packages
		WHERE change IN (?, ?) ORDER BY purl`, string(model.ChangeUpgraded), string(model.ChangeDowngraded))
	if err != nil {
		return nil, fmt.Errorf("read upgraded packages: %w", err)
	}
	defer closeRows(rows)
	seen := map[string]bool{}
	var out []*model.Package
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var pd packageData
		if err := json.Unmarshal(data, &pd); err != nil {
			return nil, fmt.Errorf("decode package: %w", err)
		}
		id, ok := PriorID(&pd.Package)
		if !ok || seen[id.PURL()] {
			continue
		}
		seen[id.PURL()] = true
		out = append(out, &model.Package{ID: id})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var todo []*model.Package
	for _, p := range out {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vet_scan_prior WHERE purl = ?`, p.ID.PURL()).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			todo = append(todo, p)
		}
	}
	return todo, nil
}

// SavePrior writes the Insights data of previous versions. A version with
// no data is not written, so a continued scan asks again.
func (s *Scan) SavePrior(ctx context.Context, pkgs []*model.Package) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, p := range pkgs {
			if p.Insight == nil {
				continue
			}
			b, err := json.Marshal(p.Insight)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO vet_scan_prior (purl, insight) VALUES (?, ?)
				ON CONFLICT (purl) DO UPDATE SET insight = excluded.insight`, p.ID.PURL(), b); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Scan) attachPrior(ctx context.Context, pkgs []*model.Package) error {
	for _, p := range pkgs {
		id, ok := PriorID(p)
		if !ok {
			continue
		}
		var b []byte
		err := s.db.QueryRowContext(ctx, `SELECT insight FROM vet_scan_prior WHERE purl = ?`, id.PURL()).Scan(&b)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read prior data: %w", err)
		}
		if err := unmarshalIf(b, &p.PreviousInsight); err != nil {
			return err
		}
	}
	return nil
}

// Capabilities yields the capabilities of the scan in id order.
func (s *Scan) Capabilities(ctx context.Context) iter.Seq2[*report.Capability, error] {
	return func(yield func(*report.Capability, error) bool) {
		s.capabilityRecords(ctx, func(r *report.Record, err error) bool {
			if err != nil {
				return yield(nil, err)
			}
			return yield(r.Capability, nil)
		})
	}
}

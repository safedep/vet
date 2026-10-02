package state

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

var _ plugin.Report = (*Scan)(nil)

// Header returns the report header, or nil before the scan sets it.
func (s *Scan) Header() *report.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.header
}

// Trailer returns the report trailer, or nil while the scan is not complete.
func (s *Scan) Trailer() *report.Trailer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trailer
}

func (s *Scan) loadMeta(ctx context.Context) error {
	var h report.Header
	okH, err := s.getMeta(ctx, metaHeader, &h)
	if err != nil {
		return err
	}
	var t report.Trailer
	okT, err := s.getMeta(ctx, metaTrailer, &t)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if okH {
		s.header = &h
	}
	if okT {
		s.trailer = &t
	}
	return nil
}

// Records yields the manifests, the packages in PURL order, the inventory,
// the findings and the diagnostics. Each query has an explicit order, so the
// same scan file always gives the same stream.
func (s *Scan) Records(ctx context.Context) iter.Seq2[*report.Record, error] {
	return func(yield func(*report.Record, error) bool) {
		stages := []func(context.Context, func(*report.Record, error) bool) bool{
			s.manifestRecords,
			s.packageRecords,
			s.inventoryRecords,
			s.findingRecords,
			s.diagnosticRecords,
		}
		for _, stage := range stages {
			if !stage(ctx, yield) {
				return
			}
		}
	}
}

func (s *Scan) manifestRecords(ctx context.Context, yield func(*report.Record, error) bool) bool {
	return s.blobRecords(ctx, `SELECT data FROM vet_scan_manifests ORDER BY seq, id`, yield,
		func(b []byte) (*report.Record, error) {
			var md manifestData
			if err := json.Unmarshal(b, &md); err != nil {
				return nil, fmt.Errorf("decode manifest: %w", err)
			}
			r := report.ManifestRecord(md.Manifest)
			return &r, nil
		})
}

func (s *Scan) inventoryRecords(ctx context.Context, yield func(*report.Record, error) bool) bool {
	return s.blobRecords(ctx, `SELECT data FROM vet_scan_inventory ORDER BY seq`, yield,
		func(b []byte) (*report.Record, error) {
			var it report.InventoryItem
			if err := json.Unmarshal(b, &it); err != nil {
				return nil, fmt.Errorf("decode inventory item: %w", err)
			}
			r := report.InventoryRecord(&it)
			return &r, nil
		})
}

func (s *Scan) diagnosticRecords(ctx context.Context, yield func(*report.Record, error) bool) bool {
	return s.blobRecords(ctx, `SELECT data FROM vet_scan_diagnostics ORDER BY seq`, yield,
		func(b []byte) (*report.Record, error) {
			var d report.Diagnostic
			if err := json.Unmarshal(b, &d); err != nil {
				return nil, fmt.Errorf("decode diagnostic: %w", err)
			}
			r := report.DiagnosticRecord(&d)
			return &r, nil
		})
}

func (s *Scan) findingRecords(ctx context.Context, yield func(*report.Record, error) bool) bool {
	for f, err := range s.Findings(ctx, plugin.FindingQuery{IncludeSuppressed: true}) {
		if err != nil {
			yield(nil, err)
			return false
		}
		if !yield(findingRecord(f), nil) {
			return false
		}
	}
	return true
}

func findingRecord(f *finding.Finding) *report.Record {
	r := report.FindingRecord(f)
	return &r
}

// blobRecords streams one JSON column. It returns false when the stream
// stops, after an error or when the caller stops.
func (s *Scan) blobRecords(ctx context.Context, query string, yield func(*report.Record, error) bool,
	decode func([]byte) (*report.Record, error),
) bool {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		yield(nil, fmt.Errorf("read records: %w", err))
		return false
	}
	defer closeRows(rows)
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			yield(nil, err)
			return false
		}
		r, err := decode(b)
		if err != nil {
			yield(nil, err)
			return false
		}
		if !yield(r, nil) {
			return false
		}
	}
	if err := rows.Err(); err != nil {
		yield(nil, err)
		return false
	}
	return true
}

// packageRecords yields one entry for each PURL. The rows come in PURL
// order, then manifest order, so one pass groups them. The package fields
// come from the first manifest that declares the package.
func (s *Scan) packageRecords(ctx context.Context, yield func(*report.Record, error) bool) bool {
	rows, err := s.db.QueryContext(ctx, `SELECT mp.manifest_id, mp.data, p.insight, p.malware, p.usage
		FROM vet_scan_packages p
		JOIN vet_scan_manifest_packages mp ON mp.purl = p.purl
		JOIN vet_scan_manifests m ON m.id = mp.manifest_id
		ORDER BY p.purl, m.seq, m.id`)
	if err != nil {
		yield(nil, fmt.Errorf("read package records: %w", err))
		return false
	}
	defer closeRows(rows)

	var cur *report.PackageEntry
	flush := func() bool {
		if cur == nil {
			return true
		}
		r := report.PackageRecord(cur)
		cur = nil
		return yield(&r, nil)
	}
	for rows.Next() {
		var manifestID string
		var data, insight, malware, usage []byte
		if err := rows.Scan(&manifestID, &data, &insight, &malware, &usage); err != nil {
			yield(nil, err)
			return false
		}
		var pd packageData
		if err := json.Unmarshal(data, &pd); err != nil {
			yield(nil, fmt.Errorf("decode package: %w", err))
			return false
		}
		purl := pd.ID.PURL()
		if cur != nil && cur.PURL == purl {
			cur.ManifestIDs = append(cur.ManifestIDs, manifestID)
			continue
		}
		if !flush() {
			return false
		}
		p := pd.Package
		for _, dec := range []error{
			unmarshalIf(insight, &p.Insight),
			unmarshalIf(malware, &p.Malware),
			unmarshalIf(usage, &p.Usage),
		} {
			if dec != nil {
				yield(nil, dec)
				return false
			}
		}
		cur = &report.PackageEntry{PURL: purl, ManifestIDs: []string{manifestID}, Package: p}
	}
	if err := rows.Err(); err != nil {
		yield(nil, err)
		return false
	}
	return flush()
}

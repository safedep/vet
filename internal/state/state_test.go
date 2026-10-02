package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), Options{StateDir: filepath.Join(t.TempDir(), "state")})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	return s
}

func newScan(t *testing.T, s *Store, target string) (*Scan, *IndexEntry) {
	t.Helper()
	scan, e, err := s.CreateScan(context.Background(), NewScan{
		TargetKey: target, TargetLabel: ".", Kind: report.ScanKindScan, OptionsHash: "h1", VetVersion: "test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, scan.Close()) })
	return scan, e
}

func lockfile() *model.Manifest {
	a := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1.0.0"}, Direct: true, Line: 3}
	b := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "b", Version: "2.0.0"}}
	g := model.NewGraph()
	g.AddRoot(a.ID)
	g.AddEdge(a.ID, b.ID)
	return &model.Manifest{
		ID: "m1", Path: "package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile,
		Packages: []*model.Package{a, b}, Graph: g,
	}
}

func TestIndexCreateGetListFind(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	_, e1 := newScan(t, s, "/repo")
	time.Sleep(2 * time.Millisecond)
	_, e2 := newScan(t, s, "/repo")
	_, e3 := newScan(t, s, "/other")

	got, err := s.Index().Get(ctx, e1.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, got.Status)
	assert.Equal(t, report.SchemaVersion, got.SchemaVersion)
	assert.FileExists(t, got.File)

	list, err := s.Index().List(ctx, ListOptions{TargetKey: "/repo"})
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, e2.ID, list[0].ID, "the newest scan comes first")

	all, err := s.Index().List(ctx, ListOptions{})
	require.NoError(t, err)
	assert.Len(t, all, 3)

	found, err := s.Index().Find(ctx, e3.ID[:6])
	require.NoError(t, err)
	assert.Equal(t, e3.ID, found.ID)

	_, err = s.Index().Get(ctx, "missing")
	assert.ErrorIs(t, err, ErrNotFound)

	got.Status = StatusCompleted
	got.Packages, got.Findings, got.Gate = 2, 1, "FAIL"
	require.NoError(t, s.Index().Update(ctx, got))
	done, err := s.Index().List(ctx, ListOptions{Statuses: []Status{StatusCompleted}})
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Equal(t, "FAIL", done[0].Gate)

	require.NoError(t, s.Index().Delete(ctx, e3.ID))
	_, err = s.Index().Get(ctx, e3.ID)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestScanFileWrites(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	scan, _ := newScan(t, s, "/repo")

	require.NoError(t, scan.PutArtifact(ctx, ArtifactRecord{Key: "a1", Kind: "file", Path: "package-lock.json", Status: ArtifactPending}))
	m := lockfile()
	require.NoError(t, scan.AddManifest(ctx, "a1", m))

	art, err := scan.Artifact(ctx, "a1")
	require.NoError(t, err)
	assert.Equal(t, ArtifactExtracted, art.Status, "the manifest commits with the done mark of its artifact")

	m.Packages[0].Malware = &model.MalwareAnalysis{Malicious: true}
	require.NoError(t, scan.SaveEnrichments(ctx, []EnrichmentResult{{Package: m.Packages[0], Enricher: "malysis", Status: "ok"}}))

	f := finding.ForPackage(finding.Meta{ControlID: "malware", Family: finding.FamilyMalware, Severity: finding.SeverityCritical, Title: "x"},
		m.Path, m.Packages[0], finding.Key{})
	require.NoError(t, scan.AddFindings(ctx, m.ID, []finding.Finding{f}))
	require.NoError(t, scan.AddDiagnostic(ctx, &report.Diagnostic{Level: report.DiagnosticWarning, Code: "c", Component: "insights"}))
	require.NoError(t, scan.AddInventory(ctx, &report.InventoryItem{Kind: report.InventorySkill, Name: "s"}))

	require.NoError(t, scan.SetStage(ctx, "extract", "done"))
	st, err := scan.Stage(ctx, "extract")
	require.NoError(t, err)
	assert.Equal(t, "done", st)

	opts := map[string]any{"include_dev": true}
	require.NoError(t, scan.SetOptions(ctx, opts))
	var back map[string]any
	ok, err := scan.Options(ctx, &back)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, true, back["include_dev"])
}

func TestOpenScanByEntryAndPath(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	scan, e := newScan(t, s, "/repo")
	require.NoError(t, scan.AddManifest(ctx, "", lockfile()))

	again, err := s.OpenScan(ctx, e)
	require.NoError(t, err)
	require.NoError(t, again.Close())

	byPath, err := OpenScanFile(ctx, e.File)
	require.NoError(t, err)
	assert.Equal(t, e.ID, byPath.ID())
	require.NoError(t, byPath.Close())

	_, err = OpenScanFile(ctx, filepath.Join(t.TempDir(), "none.db"))
	assert.Error(t, err)
}

func TestNewScanID(t *testing.T) {
	id, err := NewScanID()
	require.NoError(t, err)
	assert.Regexp(t, `^[0-9a-f]{12}$`, id)
}

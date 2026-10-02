package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// largeTree writes a monorepo: dirs directories with files source files
// each, and one package-lock.json with pkgs packages in each directory.
// The packages overlap between the directories, as in a real monorepo.
func largeTree(b *testing.B, dirs, files, pkgs int) string {
	b.Helper()
	root := b.TempDir()
	for d := range dirs {
		dir := filepath.Join(root, "services", fmt.Sprintf("svc%04d", d))
		require.NoError(b, os.MkdirAll(filepath.Join(dir, "src"), 0o700))
		for f := range files {
			require.NoError(b, os.WriteFile(filepath.Join(dir, "src", fmt.Sprintf("f%04d.js", f)), []byte("module.exports = 1\n"), 0o600))
		}
		var entries []string
		for p := range pkgs {
			entries = append(entries, fmt.Sprintf(`"node_modules/pkg%05d": {"version": "1.0.%d"}`, (d*7+p)%(pkgs*4), p%3))
		}
		lockfile := `{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"}, ` + strings.Join(entries, ", ") + `}}`
		require.NoError(b, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfile), 0o600))
	}
	return root
}

// BenchmarkScanLargeTree measures a full scan of a large tree with an
// enricher that answers at once. Run it with:
//
//	go test ./internal/engine/ -run '^$' -bench ScanLargeTree -benchtime 1x -cpuprofile cpu.out
func BenchmarkScanLargeTree(b *testing.B) {
	dir := largeTree(b, 400, 100, 200)
	for b.Loop() {
		f := newFixture(b)
		o := f.options(b, dir, &fakeEnricher{})
		o.BatchSize = 100
		res, err := Run(context.Background(), o)
		require.NoError(b, err)
		b.ReportMetric(float64(res.Entry.Packages), "packages")
		require.NoError(b, res.Scan.Close())
	}
}

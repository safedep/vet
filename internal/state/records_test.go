package state

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func recordJSON(t *testing.T, r plugin.Report) []string {
	t.Helper()
	var out []string
	for rec, err := range r.Records(context.Background()) {
		require.NoError(t, err)
		b, err := json.Marshal(rec)
		require.NoError(t, err)
		out = append(out, string(b))
	}
	return out
}

// TestRecordsMatchMemState keeps the scan file and the in-memory State of
// plugintest on one report contract.
func TestRecordsMatchMemState(t *testing.T) {
	ctx := context.Background()
	want := plugintest.SampleReport()

	s := openStore(t)
	scan, entry := newScan(t, s, "/repo")
	require.NoError(t, scan.SetHeader(ctx, want.Header()))
	for _, m := range want.ManifestList {
		require.NoError(t, scan.AddManifest(ctx, "", m))
	}
	var fs []finding.Finding
	for _, f := range want.FindingList {
		fs = append(fs, *f)
	}
	require.NoError(t, scan.AddFindings(ctx, want.ManifestList[0].ID, fs))
	for _, i := range want.InventoryList {
		require.NoError(t, scan.AddInventory(ctx, i))
	}
	for _, d := range want.DiagnosticList {
		require.NoError(t, scan.AddDiagnostic(ctx, d))
	}
	require.NoError(t, scan.SetTrailer(ctx, want.Trailer()))

	assert.Equal(t, recordJSON(t, want), recordJSON(t, scan))
	require.NoError(t, scan.Close())

	reopened, err := s.OpenScan(ctx, entry)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	assert.Equal(t, want.Header(), reopened.Header())
	assert.Equal(t, want.Trailer(), reopened.Trailer())
	assert.Equal(t, recordJSON(t, want), recordJSON(t, reopened))
}

func TestRecordsStopEarly(t *testing.T) {
	scan, _ := seed(t)
	n := 0
	for _, err := range scan.Records(context.Background()) {
		require.NoError(t, err)
		n++
		if n == 2 {
			break
		}
	}
	assert.Equal(t, 2, n)
}

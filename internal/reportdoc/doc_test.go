package reportdoc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func kinds(t *testing.T, r plugin.Report) []report.Kind {
	t.Helper()
	var out []report.Kind
	for rec, err := range r.Records(context.Background()) {
		require.NoError(t, err)
		out = append(out, rec.Kind)
	}
	return out
}

func TestLoadAndFromDocumentKeepTheRecords(t *testing.T) {
	sample := plugintest.SampleReport()
	loaded, err := Load(context.Background(), sample)
	require.NoError(t, err)
	assert.Equal(t, kinds(t, sample), kinds(t, loaded))
	assert.Equal(t, *sample.Trailer(), *loaded.Trailer())

	s, err := sinks.Builtin().New("json", nil)
	require.NoError(t, err)
	doc, err := report.Read(bytes.NewReader(plugintest.TestSink(t, s, sample)))
	require.NoError(t, err)
	fromFile := FromDocument(doc)
	assert.Equal(t, kinds(t, sample), kinds(t, fromFile))

	m, err := fromFile.Manifest(context.Background(), "m-1")
	require.NoError(t, err)
	assert.Len(t, m.Packages, 2, "the packages are linked to their manifest")
}

func TestStateQueries(t *testing.T) {
	ctx := context.Background()
	d, err := Load(ctx, plugintest.SampleReport())
	require.NoError(t, err)

	count := func(q plugin.FindingQuery) int {
		n := 0
		for _, err := range d.Findings(ctx, q) {
			require.NoError(t, err)
			n++
		}
		return n
	}
	assert.Equal(t, 2, count(plugin.FindingQuery{}))
	assert.Equal(t, 3, count(plugin.FindingQuery{IncludeSuppressed: true}))
	assert.Equal(t, 1, count(plugin.FindingQuery{MinSeverity: finding.SeverityHigh}))
	assert.Equal(t, 1, count(plugin.FindingQuery{ControlID: "unpinned-action"}))

	for f, err := range d.Findings(ctx, plugin.FindingQuery{IncludeSuppressed: true}) {
		require.NoError(t, err)
		mid, err := d.FindingManifest(ctx, f.ID)
		require.NoError(t, err)
		if f.Subject.Package != nil {
			assert.Equal(t, "m-1", mid)
		} else {
			assert.Empty(t, mid, "the workflow has no manifest in the sample")
		}
	}
}

func TestPolicyGateOnADoc(t *testing.T) {
	ctx := context.Background()
	d, err := Load(ctx, plugintest.SampleReport())
	require.NoError(t, err)
	p, err := policy.Parse("p.yml", []byte("version: 2\nsuppressions:\n  - control: malware\n    reason: r\n"))
	require.NoError(t, err)
	e := policy.NewEvaluator(p, policy.Options{FailOn: finding.SeverityCritical})
	g, err := e.Finalize(ctx, d)
	require.NoError(t, err)
	d.SetGate(g, time.Now())

	assert.Equal(t, report.GatePass, d.Trailer().Gate.Outcome, "the suppressed malware does not fail the gate")
	assert.Equal(t, 2, d.Trailer().Summary.Findings, "the earlier suppression of the cooldown finding goes")
	assert.Equal(t, 1, d.Trailer().Summary.Suppressed, "the new suppression of the malware finding comes")
}

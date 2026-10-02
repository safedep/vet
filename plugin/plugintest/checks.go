package plugintest

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// TestControl checks a control on a manifest and returns its findings. It
// checks that the control describes its control ids, that each finding is
// valid and uses a described id, that the ids are unique, and that a second
// run gives the same ids.
func TestControl(t testing.TB, c plugin.Control, m *model.Manifest, s plugin.State) []finding.Finding {
	t.Helper()

	d, ok := c.(plugin.Describer)
	require.True(t, ok, "a control implements plugin.Describer")
	infos := d.Controls()
	require.NotEmpty(t, infos, "a control describes at least one control id")

	known := map[string]plugin.ControlInfo{}
	for _, info := range infos {
		assert.NotEmpty(t, info.ID)
		assert.NotEmpty(t, info.Title, "control %s has a title", info.ID)
		assert.True(t, info.Family.Valid(), "control %s has a known family", info.ID)
		assert.True(t, info.Severity.Valid(), "control %s has a known severity", info.ID)
		known[info.ID] = info
	}

	if s == nil {
		s = NewMemState(m)
	}

	ctx := context.Background()
	first, err := c.Evaluate(ctx, m, s)
	require.NoError(t, err)

	ids := map[string]bool{}
	for _, f := range first {
		require.NoError(t, f.Validate(), "finding %s is valid", f.ID)
		_, described := known[f.ControlID]
		assert.True(t, described, "control id %s is described", f.ControlID)
		assert.False(t, ids[f.ID], "finding id %s is unique", f.ID)
		ids[f.ID] = true
	}

	second, err := c.Evaluate(ctx, m, s)
	require.NoError(t, err)
	require.Len(t, second, len(first), "a second run gives the same findings")
	for i := range first {
		assert.Equal(t, first[i].ID, second[i].ID, "a second run gives the same ids in the same order")
	}

	return first
}

// TestSink checks that a sink writes the report twice to the same bytes and
// returns them.
func TestSink(t testing.TB, s plugin.Sink, r plugin.Report) []byte {
	t.Helper()

	ctx := context.Background()
	var a, b bytes.Buffer
	require.NoError(t, s.Write(ctx, r, &a))
	require.NoError(t, s.Write(ctx, r, &b))
	assert.Equal(t, a.String(), b.String(), "a sink writes the same report to the same bytes")

	if ss, ok := s.(plugin.StreamSink); ok {
		var c bytes.Buffer
		require.NoError(t, ss.Begin(ctx, r.Header(), &c))
		for rec, err := range r.Records(ctx) {
			require.NoError(t, err)
			require.NoError(t, ss.Record(ctx, rec, &c))
		}
		require.NoError(t, ss.End(ctx, r.Trailer(), &c))
		assert.Equal(t, a.String(), c.String(), "a stream sink streams the same bytes that Write writes")
	}

	return a.Bytes()
}

// TestEnricher checks that an enricher accepts an empty batch and keeps the
// identity of each package.
func TestEnricher(t testing.TB, e plugin.Enricher, pkgs []*model.Package) {
	t.Helper()

	ctx := context.Background()
	require.NoError(t, e.Enrich(ctx, nil), "an enricher accepts an empty batch")

	ids := make([]model.PackageID, len(pkgs))
	for i, p := range pkgs {
		ids[i] = p.ID
	}
	require.NoError(t, e.Enrich(ctx, pkgs))
	for i, p := range pkgs {
		assert.Equal(t, ids[i], p.ID, "an enricher keeps the package identity")
	}
}

// TestSource checks that a source yields at least one artifact with a kind
// and a key, and that it stops when the caller stops.
func TestSource(t testing.TB, s plugin.Source) []plugin.Artifact {
	t.Helper()

	ctx := context.Background()
	var out []plugin.Artifact
	for a, err := range s.Artifacts(ctx) {
		require.NoError(t, err)
		assert.NotEmpty(t, a.Kind, "an artifact has a kind")
		assert.NotEmpty(t, a.Key, "an artifact has a target key")
		out = append(out, a)
	}
	require.NotEmpty(t, out, "a source yields at least one artifact")

	for range s.Artifacts(ctx) {
		break
	}
	return out
}

// TestPolicySource checks that each document has a name and content.
func TestPolicySource(t testing.TB, p plugin.PolicySource) []plugin.PolicyDoc {
	t.Helper()

	docs, err := p.Policies(context.Background())
	require.NoError(t, err)
	for _, d := range docs {
		assert.NotEmpty(t, d.Name, "a policy document has a name")
		assert.NotEmpty(t, d.Content, "a policy document has content")
	}
	return docs
}

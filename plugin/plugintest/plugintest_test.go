package plugintest

import (
	"context"
	"encoding/json"
	"io"
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

type everyPackage struct{}

func (everyPackage) Controls() []plugin.ControlInfo {
	return []plugin.ControlInfo{{ID: "every-package", Family: finding.FamilyHygiene, Severity: finding.SeverityInfo, Title: "Every package"}}
}

func (everyPackage) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range m.Packages {
		out = append(out, finding.ForPackage(finding.Meta{
			ControlID: "every-package", Family: finding.FamilyHygiene, Severity: finding.SeverityInfo, Title: "Every package",
		}, m.Path, p, finding.Key{}))
	}
	return out, nil
}

type jsonSink struct{}

func (jsonSink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return enc.Encode(r.Trailer())
}

type fixedSource struct{}

func (fixedSource) Artifacts(context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		for _, k := range []string{"/a", "/b"} {
			if !yield(plugin.Artifact{Kind: plugin.ArtifactDirectory, Key: k}, nil) {
				return
			}
		}
	}
}

type nopEnricher struct{}

func (nopEnricher) Enrich(context.Context, []*model.Package) error { return nil }

type fixedPolicies struct{}

func (fixedPolicies) Policies(context.Context) ([]plugin.PolicyDoc, error) {
	return []plugin.PolicyDoc{{Name: "p.yml", Content: []byte("version: 2")}}, nil
}

func TestChecksPassForConformingPlugins(t *testing.T) {
	r := SampleReport()

	fs := TestControl(t, everyPackage{}, r.ManifestList[0], r)
	assert.Len(t, fs, 2)

	out := TestSink(t, jsonSink{}, r)
	assert.NotEmpty(t, out)

	assert.Len(t, TestSource(t, fixedSource{}), 2)
	TestEnricher(t, nopEnricher{}, r.ManifestList[0].Packages)
	assert.Len(t, TestPolicySource(t, fixedPolicies{}), 1)
}

func TestSampleReport(t *testing.T) {
	r := SampleReport()
	ctx := context.Background()

	var kinds []report.Kind
	for rec, err := range r.Records(ctx) {
		require.NoError(t, err)
		require.NoError(t, rec.Validate())
		kinds = append(kinds, rec.Kind)
	}
	assert.Equal(t, []report.Kind{
		report.KindManifest, report.KindPackage, report.KindPackage, report.KindInventory, report.KindCapability,
		report.KindFinding, report.KindFinding, report.KindFinding, report.KindDiagnostic,
	}, kinds)

	tr := r.Trailer()
	assert.Equal(t, uint64(9), tr.RecordCount)
	assert.Equal(t, 1, tr.Summary.Capabilities)
	assert.Equal(t, 2, tr.Summary.Findings)
	assert.Equal(t, 1, tr.Summary.Suppressed)
	assert.Equal(t, report.GateNone, tr.Gate.Outcome)
}

func TestMemStateQueries(t *testing.T) {
	r := SampleReport()
	ctx := context.Background()

	var crit []string
	for f, err := range r.Findings(ctx, plugin.FindingQuery{MinSeverity: finding.SeverityHigh}) {
		require.NoError(t, err)
		crit = append(crit, f.ControlID)
	}
	assert.Equal(t, []string{"malware"}, crit)

	var all []string
	for f, err := range r.Findings(ctx, plugin.FindingQuery{IncludeSuppressed: true}) {
		require.NoError(t, err)
		all = append(all, f.ControlID)
	}
	assert.Len(t, all, 3)

	n := 0
	for _, err := range r.Packages(ctx, plugin.PackageQuery{ManifestID: "m-1"}) {
		require.NoError(t, err)
		n++
	}
	assert.Equal(t, 2, n)

	p, err := r.Package(ctx, model.PackageID{Ecosystem: model.EcosystemNpm, Name: "left-pad", Version: "1.3.0"})
	require.NoError(t, err)
	assert.Equal(t, "left-pad", p.ID.Name)
	_, err = r.Package(ctx, model.PackageID{Ecosystem: model.EcosystemNpm, Name: "missing"})
	assert.Error(t, err)
}

func TestDependents(t *testing.T) {
	a := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1"}}
	b := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "b", Version: "1"}}
	g := model.NewGraph()
	g.AddRoot(a.ID)
	g.AddEdge(a.ID, b.ID)
	s := NewMemState(&model.Manifest{ID: "m", Packages: []*model.Package{a, b}, Graph: g})

	var got []string
	for p, err := range s.Dependents(context.Background(), b.ID) {
		require.NoError(t, err)
		got = append(got, p.ID.Name)
	}
	assert.Equal(t, []string{"a"}, got)
}

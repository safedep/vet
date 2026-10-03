package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// capabilityEnricher finds one capability, or fails.
type capabilityEnricher struct {
	fakeEnricher
	capErr error
}

func (c *capabilityEnricher) Capabilities(context.Context) ([]report.Capability, error) {
	if c.capErr != nil {
		return nil, c.capErr
	}
	return []report.Capability{{ID: "openai.client", Tags: []string{"ai"}, Occurrences: []report.Occurrence{{File: "app.py", Line: 3}}}}, nil
}

// capabilityControl reports each capability of the application.
type capabilityControl struct{ nameControl }

func (capabilityControl) EvaluateApplication(ctx context.Context, s plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	for c, err := range s.Capabilities(ctx) {
		if err != nil {
			return nil, err
		}
		out = append(out, finding.ForApplication(finding.Meta{
			ControlID: "test-capability", Family: finding.FamilyAIBOM, Severity: finding.SeverityMedium, Title: c.ID,
		}, ".", c.ID))
	}
	return out, nil
}

func TestCapabilitiesAndApplicationControls(t *testing.T) {
	f := newFixture(t)
	en := &capabilityEnricher{}
	o := f.options(t, project(t), nil, Control{ID: "test-capability", Plugin: capabilityControl{}})
	o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: en, Local: true}}
	res := runScan(t, o)

	var caps []string
	for c, err := range res.Scan.Capabilities(context.Background()) {
		require.NoError(t, err)
		caps = append(caps, c.ID)
	}
	assert.Equal(t, []string{"openai.client"}, caps)

	var subjects []finding.SubjectKind
	for fd, err := range res.Scan.Findings(context.Background(), plugin.FindingQuery{}) {
		require.NoError(t, err)
		subjects = append(subjects, fd.Subject.Kind)
	}
	assert.Equal(t, []finding.SubjectKind{finding.SubjectApplication}, subjects)
	assert.Equal(t, 1, res.Scan.Trailer().Summary.Capabilities)
}

func TestCapabilityFinderErrorIsADiagnostic(t *testing.T) {
	f := newFixture(t)
	en := &capabilityEnricher{capErr: errors.New("parse failed")}
	o := f.options(t, project(t), nil)
	o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: en, Local: true}}
	res := runScan(t, o)

	assert.Zero(t, res.Scan.Trailer().Summary.Capabilities)
	var codes []string
	for r, err := range res.Scan.Records(context.Background()) {
		require.NoError(t, err)
		if r.Diagnostic != nil {
			codes = append(codes, r.Diagnostic.Code)
		}
	}
	assert.Contains(t, codes, CodeEnrichFailed)
}

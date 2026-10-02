// Package malysis is the enricher of SafeDep Malysis: the malware verdict
// of each package version.
package malysis

import (
	"context"
	"strings"

	malysisv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysismsg "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"

	"github.com/safedep/vet/v2/internal/plugins/enrichers/internal/client"
	"github.com/safedep/vet/v2/model"
)

// Name is the registered name of the enricher.
const Name = "malysis"

// Version changes when the mapping changes, so the cache drops old results.
const Version = "1"

// ReportURL is the public page of an analysis.
const ReportURL = "https://platform.safedep.io/community/malysis/"

// Enricher sets model.Package.Malware.
type Enricher struct {
	client  malysisv1grpc.MalwareAnalysisServiceClient
	workers int
}

// New returns the enricher over a client. workers bounds the calls of one
// batch.
func New(c malysisv1grpc.MalwareAnalysisServiceClient, workers int) *Enricher {
	return &Enricher{client: c, workers: workers}
}

// Enrich asks Malysis for the analysis of each package of the batch. A
// package with no completed analysis gets no verdict.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	return client.Each(ctx, e.workers, pkgs, func(ctx context.Context, p *model.Package) error {
		pv, err := client.PackageVersion(p.ID)
		if err != nil {
			return err
		}
		res, err := e.client.QueryPackageAnalysis(ctx, &malysisv1.QueryPackageAnalysisRequest{
			Target: &malysismsg.PackageAnalysisTarget{PackageVersion: pv},
		})
		if err != nil {
			return err
		}
		p.Malware = toAnalysis(res)
		return nil
	})
}

func toAnalysis(res *malysisv1.QueryPackageAnalysisResponse) *model.MalwareAnalysis {
	if res.GetStatus() != malysisv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETED || res.GetReport() == nil {
		return nil
	}
	inf := res.GetReport().GetInference()
	out := &model.MalwareAnalysis{
		Malicious:  inf.GetIsMalware(),
		Confidence: confidence(inf.GetConfidence()),
		Summary:    inf.GetSummary(),
		AnalysisID: res.GetAnalysisId(),
	}
	// A verification record overrules the automated verdict.
	if vr := res.GetVerificationRecord(); vr.GetIsMalware() || vr.GetIsSafe() {
		out.Malicious, out.Verified = vr.GetIsMalware(), true
	}
	if out.AnalysisID != "" {
		out.ReportURL = ReportURL + out.AnalysisID
	}
	return out
}

func confidence(c malysismsg.Report_Evidence_Confidence) string {
	if c == malysismsg.Report_Evidence_CONFIDENCE_UNSPECIFIED {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(c.String(), "CONFIDENCE_"))
}

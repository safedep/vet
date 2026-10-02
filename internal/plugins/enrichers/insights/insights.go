// Package insights is the enricher of SafeDep Insights v2: vulnerabilities,
// licenses, the publish date, deprecation, the OpenSSF Scorecard, the
// source repository, downloads and the latest version. vet does not use
// Insights v1.
package insights

import (
	"context"
	"strconv"
	"time"

	insightsv2grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"

	"github.com/safedep/vet/v2/internal/plugins/enrichers/internal/client"
	"github.com/safedep/vet/v2/model"
)

// Name is the registered name of the enricher.
const Name = "insights"

// Version changes when the mapping changes, so the cache drops old results.
const Version = "1"

// Enricher sets model.Package.Insight.
type Enricher struct {
	client  insightsv2grpc.InsightServiceClient
	workers int
}

// New returns the enricher over a client. workers bounds the calls of one
// batch.
func New(c insightsv2grpc.InsightServiceClient, workers int) *Enricher {
	return &Enricher{client: c, workers: workers}
}

// Enrich asks Insights v2 for each package of the batch.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	return client.Each(ctx, e.workers, pkgs, func(ctx context.Context, p *model.Package) error {
		pv, err := client.PackageVersion(p.ID)
		if err != nil {
			return err
		}
		res, err := e.client.GetPackageVersionInsight(ctx, &insightsv2.GetPackageVersionInsightRequest{PackageVersion: pv})
		if err != nil {
			return err
		}
		p.Insight = toInsight(res.GetInsight())
		return nil
	})
}

func toInsight(in *packagev1.PackageVersionInsight) *model.Insight {
	if in == nil {
		return nil
	}
	out := &model.Insight{
		Deprecated: in.GetDeprecated(),
		Downloads:  int64(in.GetDownloadCount()),
	}
	if ts := in.GetPublishedAt(); ts != nil {
		t := ts.AsTime().UTC()
		out.PublishedAt = &t
	}
	for _, l := range in.GetLicenses().GetLicenses() {
		if id := l.GetLicenseId(); id != "" {
			out.Licenses = append(out.Licenses, id)
		}
	}
	for _, v := range in.GetVulnerabilities() {
		out.Vulnerabilities = append(out.Vulnerabilities, toVulnerability(v))
	}
	for _, pi := range in.GetProjectInsights() {
		if out.SourceRepo == "" {
			out.SourceRepo = pi.GetProject().GetUrl()
		}
		if sc := pi.GetScorecard(); sc != nil && out.Scorecard == nil {
			card := &model.Scorecard{Score: float64(sc.GetScore()), Checks: map[string]float64{}}
			for _, c := range sc.GetChecks() {
				card.Checks[c.GetName()] = float64(c.GetScore())
			}
			out.Scorecard = card
		}
	}
	out.LatestVersion = latest(in.GetAvailableVersions())
	return out
}

// latest returns the default version of the registry, or the version with
// the latest publish date.
func latest(vs []*packagev1.PackageAvailableVersion) string {
	var best string
	var bestAt time.Time
	for _, v := range vs {
		if v.GetDefaultVersion() {
			return v.GetVersion()
		}
		if at := v.GetPublishedAt().AsTime(); v.GetPublishedAt() != nil && at.After(bestAt) {
			best, bestAt = v.GetVersion(), at
		}
	}
	return best
}

func toVulnerability(v *vulnerabilityv1.Vulnerability) model.Vulnerability {
	out := model.Vulnerability{ID: v.GetId().GetValue(), Summary: v.GetSummary()}
	for _, a := range v.GetAliases() {
		if a.GetValue() != "" {
			out.Aliases = append(out.Aliases, a.GetValue())
		}
	}
	for _, s := range v.GetSeverities() {
		if risk := riskName(s.GetRisk()); risk != "" && severityRank(risk) > severityRank(out.Severity) {
			out.Severity = risk
		}
		if score, err := strconv.ParseFloat(s.GetScore(), 64); err == nil && score > out.CVSS {
			out.CVSS = score
		}
	}
	// gap G1: an Insights v2 vulnerability has no fixed versions, so
	// out.Fixed stays empty and a finding cannot name the fix version.
	return out
}

func riskName(r vulnerabilityv1.Severity_Risk) string {
	switch r {
	case vulnerabilityv1.Severity_RISK_CRITICAL:
		return "critical"
	case vulnerabilityv1.Severity_RISK_HIGH:
		return "high"
	case vulnerabilityv1.Severity_RISK_MEDIUM:
		return "medium"
	case vulnerabilityv1.Severity_RISK_LOW:
		return "low"
	}
	return ""
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

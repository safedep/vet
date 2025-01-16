package scanner

import (
	"context"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"
	"github.com/safedep/dry/semver"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"google.golang.org/grpc"
)

type insightsBasedPackageEnricherV2 struct {
	cc     *grpc.ClientConn
	client insightsv2grpc.InsightServiceClient
}

// NewInsightBasedPackageEnricherV2 creates a new instance of the enricher using
// Insights API v2. It requires a pre-configured gRPC client connection.
func NewInsightBasedPackageEnricherV2(cc *grpc.ClientConn) (PackageMetaEnricher, error) {
	client := insightsv2grpc.NewInsightServiceClient(cc)
	return &insightsBasedPackageEnricherV2{
		cc:     cc,
		client: client,
	}, nil
}

func (e *insightsBasedPackageEnricherV2) Name() string {
	return "Insights API v2"
}

// Enrich will enrich the package using Insights V2 API. However, most of the
// analysers and reporters in vet are coupled with Insights V1 data model. Till
// we are able to drive a major refactor to decouple them, we need to convert V2
// data model to V1 data model while preserving the V2 data. This will ensure
//
// - Existing analysers and reporters continue to work without any changes.
// - We can start using V2 data model in new analysers and reporters.
func (e *insightsBasedPackageEnricherV2) Enrich(pkg *models.Package,
	cb PackageDependencyCallbackFn) error {
	res, err := e.client.GetPackageVersionInsight(context.Background(),
		&insightsv2.GetPackageVersionInsightRequest{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: pkg.GetControlTowerSpecEcosystem(),
					Name:      pkg.GetName(),
				},
				Version: pkg.GetVersion(),
			},
		})

	if err != nil {
		logger.Debugf("Failed to enrich package: %s/%s: %v",
			pkg.GetName(), pkg.GetVersion(), err)
		return err
	}

	return e.applyInsights(pkg, res)
}

func (e *insightsBasedPackageEnricherV2) applyInsights(pkg *models.Package,
	res *insightsv2.GetPackageVersionInsightResponse) error {
	// Convert the V2 insights to V1 insights for backward compatibility
	insightsv1, err := e.convertInsightsV2ToV1(res.GetInsight())
	if err != nil {
		return err
	}

	// Apply the V1 insights to the package
	pkg.Insights = insightsv1

	// Apply provenance if available
	pkg.Provenances = e.getProvenances(res)

	// Finally, store the new insights model :)
	pkg.InsightsV2 = res.GetInsight()
	return nil
}

func (e *insightsBasedPackageEnricherV2) getProvenances(res *insightsv2.GetPackageVersionInsightResponse) []*models.Provenance {
	pkgProvenances := []*models.Provenance{}

	provenances := res.GetInsight().GetSlsaProvenances()
	if len(provenances) == 0 {
		return pkgProvenances
	}

	for _, p := range provenances {
		pkgProvenances = append(pkgProvenances, &models.Provenance{
			Type:             models.ProvenanceTypeSlsa,
			SourceRepository: p.GetSourceRepository(),
			CommitSHA:        p.GetCommitSha(),
			Url:              p.GetUrl(),
			Verified:         p.GetVerified(),
		})
	}

	return pkgProvenances
}

func (e *insightsBasedPackageEnricherV2) convertInsightsV2ToV1(pvi *packagev1.PackageVersionInsight) (*insightapi.PackageVersionInsight, error) {
	insights := &insightapi.PackageVersionInsight{}

	// Dependencies
	distance := 1
	dependencies := []insightapi.PackageDependency{}
	for _, d := range pvi.GetDependencies() {
		dependencies = append(dependencies, insightapi.PackageDependency{
			PackageVersion: &insightapi.PackageVersion{
				Ecosystem: e.mapEcosystem(d.GetPackage().GetEcosystem()),
				Name:      d.GetPackage().GetName(),
				Version:   d.GetVersion(),
			},

			// This is missing in insights v2 or should we use the dependency graph?
			Distance: &distance,
		})
	}

	insights.Dependencies = &dependencies

	// Dependents
	// We don't have dependents in Insights V2 model

	// Licenses
	licenses := []insightapi.License{}
	for _, l := range pvi.GetLicenses().GetLicenses() {
		licenses = append(licenses, insightapi.License(l.GetLicenseId()))
	}

	insights.Licenses = &licenses

	// Package Version
	// Why do we need this inside insights?

	// Current Version
	// We will pick the latest version from available versions.
	// This will work for most cases but not for all.
	currentVersion := ""
	for _, v := range pvi.GetAvailableVersions() {
		if currentVersion == "" {
			currentVersion = v.GetVersion()
			continue
		}

		if semver.IsAhead(currentVersion, v.GetVersion()) {
			currentVersion = v.GetVersion()
		}
	}

	insights.PackageCurrentVersion = &currentVersion

	// Projects
	projects := []insightapi.PackageProjectInfo{}
	for _, p := range pvi.GetProjectInsights() {
		projectName := p.GetProject().GetName()
		projectDisplayName := "" // Missing
		link := p.GetProject().GetUrl()
		forks := int(p.GetForks())
		stars := int(p.GetStars())
		issues := int(p.GetIssues().GetOpen())
		projectType := "GITHUB" // Old policy compatibility
		if p.GetProject().GetType() == packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITLAB {
			projectType = "GITLAB"
		} else if p.GetProject().GetType() == packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_BITBUCKET {
			projectType = "BITBUCKET"
		}

		projects = append(projects, insightapi.PackageProjectInfo{
			Name:        &projectName,
			DisplayName: &projectDisplayName,
			Link:        &link,
			Forks:       &forks,
			Stars:       &stars,
			Issues:      &issues,
			Type:        &projectType,
		})
	}

	insights.Projects = &projects

	// Scorecard - Wrong modelling here. Scorecard is part of project
	// To work around, we will only use the first project's scorecard
	scorecard := insightapi.Scorecard{}
	if len(projects) > 0 {
		sourceProject := pvi.GetProjectInsights()[0]
		sourceScorecard := sourceProject.GetScorecard()
		sourceScorecardVersion := insightapi.ScorecardVersion(sourceScorecard.GetScorecardVersion().GetVersion())
		sourceScorecardScore := sourceScorecard.GetScore()
		sourceScorecardRepoCommit := sourceScorecard.GetRepo().GetCommit()
		sourceScorecardRepoName := sourceScorecard.GetRepo().GetName()

		checks := []insightapi.ScorecardV2Check{}
		for _, c := range sourceScorecard.GetChecks() {
			checkName := insightapi.ScorecardV2CheckName(c.GetName())
			checkReason := c.GetReason()
			checkScore := c.GetScore()
			checks = append(checks, insightapi.ScorecardV2Check{
				Name:   &checkName,
				Reason: &checkReason,
				Score:  &checkScore,
			})
		}

		scorecard = insightapi.Scorecard{
			Version: &sourceScorecardVersion,
			Content: &insightapi.ScorecardContentV2{
				Score: &sourceScorecardScore,
				Repository: &insightapi.ScorecardContentV2Repository{
					Commit: &sourceScorecardRepoCommit,
					Name:   &sourceScorecardRepoName,
				},
				Scorecard: &insightapi.ScorecardContentV2Version{
					// Not available in Insights v2
				},
				Checks: &checks,
			},
		}
	}

	insights.Scorecard = &scorecard

	// Vulnerabilities
	vulnerabilities := []insightapi.PackageVulnerability{}
	for _, v := range pvi.GetVulnerabilities() {
		vulnId := v.GetId().GetValue()
		aliases := []string{}
		related := []string{}
		summary := v.GetSummary()

		for _, a := range v.GetAliases() {
			aliases = append(aliases, a.GetValue())
		}

		for _, r := range v.GetRelated() {
			related = append(related, r.GetValue())
		}

		packageVulnerability := insightapi.PackageVulnerability{
			Id:      &vulnId,
			Aliases: &aliases,
			Related: &related,
			Summary: &summary,
			// How to map Severities which is a naked struct?
		}

		severities := []struct {
			Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
			Score *string                                        `json:"score,omitempty"`
			Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
		}{}

		for _, sev := range v.GetSeverities() {
			sevScore := sev.GetScore()
			sevType := insightapi.PackageVulnerabilitySeveritiesType("")
			sevRisk := insightapi.PackageVulnerabilitySeveritiesRisk("")

			switch sev.GetRisk() {
			case vulnerabilityv1.Severity_RISK_CRITICAL:
				sevRisk = insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL
			case vulnerabilityv1.Severity_RISK_HIGH:
				sevRisk = insightapi.PackageVulnerabilitySeveritiesRiskHIGH
			case vulnerabilityv1.Severity_RISK_MEDIUM:
				sevRisk = insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM
			case vulnerabilityv1.Severity_RISK_LOW:
				sevRisk = insightapi.PackageVulnerabilitySeveritiesRiskLOW
			default:
				sevRisk = insightapi.PackageVulnerabilitySeveritiesRiskUNKNOWN
			}

			switch sev.GetType() {
			case vulnerabilityv1.Severity_TYPE_CVSS_V2:
				sevType = insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2
			case vulnerabilityv1.Severity_TYPE_CVSS_V3:
				sevType = insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3
			default:
				sevType = insightapi.PackageVulnerabilitySeveritiesTypeUNSPECIFIED
			}

			severities = append(severities, struct {
				Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
				Score *string                                        `json:"score,omitempty"`
				Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
			}{
				Risk:  &sevRisk,
				Score: &sevScore,
				Type:  &sevType,
			})
		}

		packageVulnerability.Severities = &severities
		vulnerabilities = append(vulnerabilities, packageVulnerability)
	}

	insights.Vulnerabilities = &vulnerabilities
	return insights, nil
}

func (e *insightsBasedPackageEnricherV2) Wait() error {
	return nil
}

// Should this be in models?
func (e *insightsBasedPackageEnricherV2) mapEcosystem(ecosystem packagev1.Ecosystem) string {
	return models.GetModelEcosystem(ecosystem)
}

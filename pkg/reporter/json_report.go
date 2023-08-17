package reporter

import (
	"fmt"
	"os"
	"encoding/json"
	"sync"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/exceptions"
)


type JsonReportingConfig struct {
	Path string
}

// Highlevel Json Structure
type jsonTemplateInput struct {
	Remediations       map[string][]jsonTemplateInputRemediation `json:"remediations"`         // Remediations
	Summary            jsonTemplateInputResultSummary 			 `json:"summary"`              // Summary
	Violations         []jsonTemplateInputViolation              `json:"violations"`           // Violations
}


type jsonTemplateInputViolation struct {
	Ecosystem string `json:"ecosystem"` // Ecosystem of the package
	PkgName   string `json:"pkg_name"`  // Package name
	Message   string `json:"message"`   // Violation message
}

type jsonTemplateInputRemediation struct {
	Pkg                *models.Package `json:"pkg"`                  // Package details
	PkgRemediationName string          `json:"pkg_remediation_name"` // Remediation name
	Score              int             `json:"score"`                // Score
	Tags               string          `json:"tags"`                 // Tags
}

type jsonTemplateInputManifestResultSummary struct {
	Ecosystem               string `json:"ecosystem"`                 // Ecosystem
	PackageCount            int    `json:"package_count"`             // Package count
	PackageWithIssuesCount  int    `json:"package_with_issues_count"` // Packages with issues count
}

type jsonTemplateInputResultSummary struct {
	Manifests 				 map[string]jsonTemplateInputManifestResultSummary `json:"manifests"` 
	ManifestsCount			int    `json:"manifests_count"`      // Manifests count
	PackagesCount      		int    `json:"packages_count"`       // Packages count
	CriticalVulnCount  		int    `json:"critical_vuln_count"`  // Critical vulnerabilities count
	HighVulnCount      		int    `json:"high_vuln_count"`      // High vulnerabilities count
	OtherVulnCount     		int    `json:"other_vuln_count"`     // Other vulnerabilities count
	UnpopularLibsCount 		int    `json:"unpopular_libs_count"` // Unpopular libraries count
	DriftLibsCount     		int    `json:"drift_libs_count"`     // Drifting libraries count
	ExemptedLibs       		int    `json:"exempted_libs"`        // Exempted libraries count
}

// Json reporter is built on top of summary reporter to
// provide extended visibility
type jsonReportGenerator struct {
	m               sync.Mutex
	config          JsonReportingConfig
	summaryReporter Reporter
	templateInput   jsonTemplateInput
	violations      map[string]*analyzer.AnalyzerEvent
}

func NewJsonReportGenerator(config JsonReportingConfig) (Reporter, error) {
	summaryReporter, _ := NewSummaryReporter()
	return &jsonReportGenerator{
		config:          config,
		summaryReporter: summaryReporter,
		violations:      make(map[string]*analyzer.AnalyzerEvent),
	}, nil
}

func (r *jsonReportGenerator) Name() string {
	return "Json Report Generator"
}

func (r *jsonReportGenerator) AddManifest(manifest *models.PackageManifest) {
	r.summaryReporter.AddManifest(manifest)
}

func (r *jsonReportGenerator) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsFilterMatch() {
		return
	}

	if event.Package == nil {
		return
	}

	if event.Package.Manifest == nil {
		return
	}

	pkgId := event.Package.Id()
	if _, ok := r.violations[pkgId]; ok {
		return
	}

	r.violations[pkgId] = event
}

func (r *jsonReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *jsonReportGenerator) Finish() error {
	logger.Infof("Generating consolidated Json report: %s", r.config.Path)

	var sr *summaryReporter
	var ok bool

	if sr, ok = r.summaryReporter.(*summaryReporter); !ok {
		return fmt.Errorf("failed to duck type Reporter to summaryReporter")
	}

	sortedList := sr.sortedRemediations()
	remediations := map[string][]jsonTemplateInputRemediation{}
	manifest_summaries := map[string]jsonTemplateInputManifestResultSummary{}

	for _, s := range sortedList {
		mp := s.pkg.Manifest.Path
		remediations[mp] = append(remediations[mp], jsonTemplateInputRemediation{
			Pkg:                s.pkg,
			PkgRemediationName: sr.packageNameForRemediationAdvice(s.pkg),
			Score:              s.score,
			Tags:				fmt.Sprintf("%s", s.tags),
		})

		if _, ok := manifest_summaries[mp]; !ok {
			manifest_summaries[mp] = jsonTemplateInputManifestResultSummary{
				Ecosystem:    string(s.pkg.Ecosystem),
				PackageCount: len(s.pkg.Manifest.Packages),
			}
		} else {
			s := manifest_summaries[mp]
			s.PackageWithIssuesCount += 1
			manifest_summaries[mp] = s
		}
	}

	violations := []jsonTemplateInputViolation{}
	for _, v := range r.violations {
		var msg string
		if msg, ok = v.Message.(string); !ok {
			continue
		}

		violations = append(violations, jsonTemplateInputViolation{
			Ecosystem: string(v.Package.Ecosystem),
			PkgName:   fmt.Sprintf("%s@%s", v.Package.Name, v.Package.Version),
			Message:   msg,
		})
	}

	summaries := jsonTemplateInputResultSummary{Manifests: manifest_summaries}
	summaries.ManifestsCount = len(manifest_summaries)
	summaries.PackagesCount = sr.summary.packages
	summaries.CriticalVulnCount = sr.summary.vulns.critical
	summaries.HighVulnCount = sr.summary.vulns.high
	summaries.OtherVulnCount = sr.summary.vulns.medium + sr.summary.vulns.low 
	summaries.UnpopularLibsCount = sr.summary.metrics.unpopular
	summaries.DriftLibsCount = sr.summary.metrics.drifts
	summaries.ExemptedLibs = exceptions.ActiveCount()

	templateInput := jsonTemplateInput{
			Remediations:   remediations,
			Summary:        summaries,
			Violations:     violations,
		}

	b, err := json.Marshal(templateInput)
    if err != nil {
		return err
    }

	file, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}

	defer file.Close()
	_, err = file.Write(b)
	return err
}

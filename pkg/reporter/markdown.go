package reporter

import (
	"fmt"
	"os"
	"sync"
	"text/template"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/exceptions"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"

	_ "embed"
)

//go:embed markdown.template.md
var markdownTemplate string

type MarkdownReportingConfig struct {
	Path string
}

type markdownTemplateInputViolation struct {
	Ecosystem string
	PkgName   string
	Message   string
}

type markdownTemplateInputRemediation struct {
	Pkg                *models.Package
	PkgRemediationName string
	Score              int
	Tags               string
}

type markdownTemplateInputResultSummary struct {
	Ecosystem              string
	PackageCount           int
	PackageWithIssuesCount int
}

type markdownTemplateInput struct {
	Remediations       map[string][]markdownTemplateInputRemediation
	Summary            map[string]markdownTemplateInputResultSummary
	Violations         []markdownTemplateInputViolation
	ManifestsCount     int
	PackagesCount      int
	CriticalVulnCount  int
	HighVulnCount      int
	OtherVulnCount     int
	UnpopularLibsCount int
	DriftLibsCount     int
	ExemptedLibs       int
}

// Markdown reporter is built on top of summary reporter to
// provide extended visibility
type markdownReportGenerator struct {
	m               sync.Mutex
	config          MarkdownReportingConfig
	summaryReporter Reporter
	templateInput   markdownTemplateInput
	violations      map[string]*analyzer.AnalyzerEvent
}

func NewMarkdownReportGenerator(config MarkdownReportingConfig) (Reporter, error) {
	summaryReporter, _ := NewSummaryReporter(SummaryReporterConfig{
		MaxAdvice: summaryReportMaxUpgradeAdvice,
	})

	return &markdownReportGenerator{
		config:          config,
		summaryReporter: summaryReporter,
		violations:      make(map[string]*analyzer.AnalyzerEvent),
	}, nil
}

func (r *markdownReportGenerator) Name() string {
	return "Markdown Report Generator"
}

func (r *markdownReportGenerator) AddManifest(manifest *models.PackageManifest) {
	r.summaryReporter.AddManifest(manifest)
}

func (r *markdownReportGenerator) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
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

func (r *markdownReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *markdownReportGenerator) Finish() error {
	logger.Infof("Generating consolidated markdown report: %s", r.config.Path)

	var sr *summaryReporter
	var ok bool

	if sr, ok = r.summaryReporter.(*summaryReporter); !ok {
		return fmt.Errorf("failed to duck type Reporter to summaryReporter")
	}

	sortedList := sr.sortedRemediations()
	remediations := map[string][]markdownTemplateInputRemediation{}
	summaries := map[string]markdownTemplateInputResultSummary{}

	for _, s := range sortedList {
		mp := s.pkg.Manifest.Path
		remediations[mp] = append(remediations[mp], markdownTemplateInputRemediation{
			Pkg:                s.pkg,
			PkgRemediationName: sr.packageNameForRemediationAdvice(s.pkg),
			Score:              s.score,
			Tags:               fmt.Sprintf("%s", s.tags),
		})

		if _, ok := summaries[mp]; !ok {
			summaries[mp] = markdownTemplateInputResultSummary{
				Ecosystem:    string(s.pkg.Ecosystem),
				PackageCount: len(s.pkg.Manifest.Packages),
			}
		} else {
			s := summaries[mp]
			s.PackageWithIssuesCount += 1
			summaries[mp] = s
		}
	}

	violations := []markdownTemplateInputViolation{}
	for _, v := range r.violations {
		var msg string
		if msg, ok = v.Message.(string); !ok {
			continue
		}

		violations = append(violations, markdownTemplateInputViolation{
			Ecosystem: string(v.Package.Ecosystem),
			PkgName:   fmt.Sprintf("%s@%s", v.Package.Name, v.Package.Version),
			Message:   msg,
		})
	}

	tmpl, err := template.New("markdown").Parse(markdownTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}

	defer file.Close()
	return tmpl.Execute(file, markdownTemplateInput{
		Remediations:       remediations,
		ManifestsCount:     sr.summary.manifests,
		PackagesCount:      sr.summary.packages,
		CriticalVulnCount:  sr.summary.vulns.critical,
		HighVulnCount:      sr.summary.vulns.high,
		OtherVulnCount:     sr.summary.vulns.medium + sr.summary.vulns.low,
		UnpopularLibsCount: sr.summary.metrics.unpopular,
		DriftLibsCount:     sr.summary.metrics.drifts,
		ExemptedLibs:       exceptions.ActiveCount(),
		Summary:            summaries,
		Violations:         violations,
	})
}

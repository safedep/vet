package reporter

import (
	"fmt"
	"os"
	"sync"
	"text/template"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"

	_ "embed"
)

//go:embed markdown.template.md
var markdownTemplate string

type MarkdownReportingConfig struct {
	Path string
}

type markdownTemplateInputRemediation struct {
	Pkg                *models.Package
	PkgRemediationName string
	Score              int
}

type markdownTemplateInput struct {
	Remediations   []markdownTemplateInputRemediation
	ManifestsCount int
	PackagesCount  int
}

// Markdown reporter is built on top of summary reporter to
// provide extended visibility
type markdownReportGenerator struct {
	m               sync.Mutex
	config          MarkdownReportingConfig
	summaryReporter Reporter
	templateInput   markdownTemplateInput
}

func NewMarkdownReportGenerator(config MarkdownReportingConfig) (Reporter, error) {
	summaryReporter, _ := NewSummaryReporter()
	return &markdownReportGenerator{
		config:          config,
		summaryReporter: summaryReporter,
	}, nil
}

func (r *markdownReportGenerator) Name() string {
	return "Markdown Report Generator"
}

func (r *markdownReportGenerator) AddManifest(manifest *models.PackageManifest) {
	r.summaryReporter.AddManifest(manifest)
}

func (r *markdownReportGenerator) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *markdownReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *markdownReportGenerator) Finish() error {
	logger.Infof("Generating consolidated markdown report: %s", r.config.Path)

	var sr *summaryReporter
	var ok bool

	if sr, ok = r.summaryReporter.(*summaryReporter); !ok {
		return fmt.Errorf("failed to duck type Reporter to summaryReporter")
	}

	sortedList := sr.sortedRemediations()
	remediations := []markdownTemplateInputRemediation{}

	for _, s := range sortedList {
		remediations = append(remediations, markdownTemplateInputRemediation{
			Pkg:                s.pkg,
			PkgRemediationName: sr.packageNameForRemediationAdvice(s.pkg),
			Score:              s.score,
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
		Remediations:   remediations,
		ManifestsCount: sr.summary.manifests,
		PackagesCount:  sr.summary.packages,
	})
}

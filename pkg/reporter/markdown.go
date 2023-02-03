package reporter

import (
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

type markdownTemplateInput struct {
	Manifests      []*models.PackageManifest
	AnalyzerEvents []*analyzer.AnalyzerEvent
	PolicyEvents   []*policy.PolicyEvent
}

type markdownReportGenerator struct {
	m             sync.Mutex
	config        MarkdownReportingConfig
	templateInput markdownTemplateInput
}

func NewMarkdownReportGenerator(config MarkdownReportingConfig) (Reporter, error) {
	return &markdownReportGenerator{
		config: config,
		templateInput: markdownTemplateInput{
			Manifests:      make([]*models.PackageManifest, 0),
			AnalyzerEvents: make([]*analyzer.AnalyzerEvent, 0),
			PolicyEvents:   make([]*policy.PolicyEvent, 0),
		},
	}, nil
}

func (r *markdownReportGenerator) Name() string {
	return "Markdown Report Generator"
}

func (r *markdownReportGenerator) AddManifest(manifest *models.PackageManifest) {
	r.m.Lock()
	defer r.m.Unlock()
	r.templateInput.Manifests = append(r.templateInput.Manifests, manifest)
}

func (r *markdownReportGenerator) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.m.Lock()
	defer r.m.Unlock()
	r.templateInput.AnalyzerEvents = append(r.templateInput.AnalyzerEvents, event)
}

func (r *markdownReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {
	r.m.Lock()
	defer r.m.Unlock()
	r.templateInput.PolicyEvents = append(r.templateInput.PolicyEvents, event)
}

func (r *markdownReportGenerator) Finish() error {
	logger.Infof("Generating consolidated markdown report: %s", r.config.Path)

	tmpl, err := template.New("markdown").Parse(markdownTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}

	defer file.Close()
	return tmpl.Execute(file, r.templateInput)
}

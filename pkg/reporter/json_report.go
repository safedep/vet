package reporter

import (
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/utils"
	schema "github.com/safedep/vet/gen/jsonreport"
	modelspec "github.com/safedep/vet/gen/models"
	"github.com/safedep/vet/gen/violations"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

type JsonReportingConfig struct {
	Path string
}

// Json reporter is built on top of summary reporter to
// provide extended visibility
type jsonReportGenerator struct {
	config     JsonReportingConfig
	repository Reporter
	violations map[string][]*analyzer.AnalyzerEvent
}

func NewJsonReportGenerator(config JsonReportingConfig) (Reporter, error) {
	sr, err := NewSummaryReporter()
	if err != nil {
		return nil, err
	}

	return &jsonReportGenerator{
		config:     config,
		repository: sr,
		violations: make(map[string][]*analyzer.AnalyzerEvent),
	}, nil
}

func (r *jsonReportGenerator) Name() string {
	return "JSON Report Generator"
}

func (r *jsonReportGenerator) AddManifest(manifest *models.PackageManifest) {
	r.repository.AddManifest(manifest)
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

	if event.Filter == nil {
		return
	}

	pkgId := event.Package.Id()
	if _, ok := r.violations[pkgId]; !ok {
		r.violations[pkgId] = []*analyzer.AnalyzerEvent{}
	}

	r.violations[pkgId] = append(r.violations[pkgId], event)
}

func (r *jsonReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *jsonReportGenerator) Finish() error {
	logger.Infof("Generating consolidated Json report: %s", r.config.Path)

	var sr *summaryReporter
	var ok bool

	if sr, ok = r.repository.(*summaryReporter); !ok {
		return fmt.Errorf("failed to duck type Reporter to summaryReporter")
	}

	sortedList := sr.sortedRemediations()
	report := schema.Report{
		Meta: &schema.ReportMeta{
			ToolName:    "vet",
			ToolVersion: "latest",
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		},
		Violations: []*violations.Violation{},
		Advices:    []*schema.RemediationAdvice{},
	}

	for _, s := range sortedList {
		pkgInsight := utils.SafelyGetValue(s.pkg.Insights)

		report.Advices = append(report.Advices, &schema.RemediationAdvice{
			Package: &modelspec.Package{
				Name:    s.pkg.Name,
				Version: s.pkg.Version,
			},
			TargetPackageName: sr.packageNameForRemediationAdvice(s.pkg),
			TargetVersion:     utils.SafelyGetValue(pkgInsight.PackageCurrentVersion),
		})

	}

	for _, events := range r.violations {
		if len(events) == 0 {
			continue
		}

		for _, v := range events {
			var msg string
			if msg, ok = v.Message.(string); !ok {
				continue
			}

			report.Violations = append(report.Violations, &violations.Violation{
				CheckType: v.Filter.GetCheckType(),
				Message:   msg,
				Package: &modelspec.Package{
					Name:    v.Package.Name,
					Version: v.Package.Version,
				},
			})
		}
	}

	b, err := utils.ToPbJson(&report, "")
	if err != nil {
		return err
	}

	file, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}

	defer file.Close()
	_, err = file.WriteString(b)
	return err
}

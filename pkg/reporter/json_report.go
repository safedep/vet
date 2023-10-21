package reporter

import (
	"os"
	"time"

	"github.com/safedep/dry/utils"
	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	schema "github.com/safedep/vet/gen/jsonreport"
	modelspec "github.com/safedep/vet/gen/models"
	"github.com/safedep/vet/gen/violations"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/remediations"
	"k8s.io/utils/strings/slices"
)

type JsonReportingConfig struct {
	Path string
}

// Json reporter is built on top of summary reporter to
// provide extended visibility
type jsonReportGenerator struct {
	config     JsonReportingConfig
	repository Reporter

	manifests map[string]*jsonreportspec.PackageManifestReport
	packages  map[string]*jsonreportspec.PackageReport
}

func NewJsonReportGenerator(config JsonReportingConfig) (Reporter, error) {
	sr, err := NewSummaryReporter()
	if err != nil {
		return nil, err
	}

	return &jsonReportGenerator{
		config:     config,
		repository: sr,
		manifests:  make(map[string]*schema.PackageManifestReport),
		packages:   make(map[string]*schema.PackageReport),
	}, nil
}

func (r *jsonReportGenerator) Name() string {
	return "JSON Report Generator"
}

func (r *jsonReportGenerator) AddManifest(manifest *models.PackageManifest) {
	r.repository.AddManifest(manifest)

	if _, ok := r.manifests[manifest.Id()]; !ok {
		r.manifests[manifest.Id()] = &jsonreportspec.PackageManifestReport{
			Id:        manifest.Id(),
			Path:      manifest.Path,
			Ecosystem: manifest.GetSpecEcosystem(),
		}
	}

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(p *models.Package) error {
		if _, ok := r.packages[p.Id()]; !ok {
			r.packages[p.Id()] = r.buildJsonPackageReportFromPackage(p)
		}

		if !slices.Contains(r.packages[p.Id()].Manifests, manifest.Id()) {
			r.packages[p.Id()].Manifests = append(r.packages[p.Id()].Manifests, manifest.Id())
		}

		return nil
	})

	if err != nil {
		logger.Warnf("Failed to enumerate manifest packages: %v", err)
	}
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

	if _, ok := r.packages[event.Package.Id()]; !ok {
		r.packages[event.Package.Id()] = r.buildJsonPackageReportFromPackage(event.Package)
	}

	// We avoid duplicate violation for a package. Duplicates can occur because same package
	// is in multiple manifests hence raising same violation
	v := utils.FindAnyWith(r.packages[event.Package.Id()].Violations, func(item **violations.Violation) bool {
		return ((*item).GetFilter().GetName() == event.Filter.GetName())
	})
	if v != nil {
		return
	}

	violation := &violations.Violation{
		CheckType: event.Filter.GetCheckType(),
		Filter:    event.Filter,
	}

	r.packages[event.Package.Id()].Violations = append(r.packages[event.Package.Id()].Violations, violation)

	remediationGenerator := remediations.NewStaticRemediationGenerator()
	advice, err := remediationGenerator.Advice(event.Package, violation)
	if err != nil {
		logger.Warnf("Failed to generate remediation for %s due to %v",
			event.Package.ShortName(), err)
	} else {
		r.packages[event.Package.Id()].Advices = append(r.packages[event.Package.Id()].Advices, advice)
	}
}

func (r *jsonReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *jsonReportGenerator) Finish() error {
	logger.Infof("Generating consolidated Json report: %s", r.config.Path)

	report := schema.Report{
		Meta: &schema.ReportMeta{
			ToolName:    "vet",
			ToolVersion: "latest",
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		},
		Packages:  make([]*schema.PackageReport, 0),
		Manifests: make([]*schema.PackageManifestReport, 0),
	}

	for _, pm := range r.manifests {
		report.Manifests = append(report.Manifests, pm)
	}

	for _, p := range r.packages {
		report.Packages = append(report.Packages, p)
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

func (j *jsonReportGenerator) buildJsonPackageReportFromPackage(p *models.Package) *jsonreportspec.PackageReport {
	return &jsonreportspec.PackageReport{
		Package: &modelspec.Package{
			Ecosystem: p.GetSpecEcosystem(),
			Name:      p.GetName(),
			Version:   p.GetVersion(),
		},
		Violations: make([]*violations.Violation, 0),
		Advices:    make([]*schema.RemediationAdvice, 0),
	}
}

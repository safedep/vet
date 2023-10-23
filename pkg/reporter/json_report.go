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
	config       JsonReportingConfig
	remediations remediations.RemediationGenerator

	manifests map[string]*jsonreportspec.PackageManifestReport
	packages  map[string]*jsonreportspec.PackageReport
}

func NewJsonReportGenerator(config JsonReportingConfig) (Reporter, error) {
	return &jsonReportGenerator{
		config:       config,
		remediations: remediations.NewStaticRemediationGenerator(),
		manifests:    make(map[string]*schema.PackageManifestReport),
		packages:     make(map[string]*schema.PackageReport),
	}, nil
}

func (r *jsonReportGenerator) Name() string {
	return "JSON Report Generator"
}

func (r *jsonReportGenerator) AddManifest(manifest *models.PackageManifest) {
	manifestId := manifest.Id()
	if _, ok := r.manifests[manifestId]; !ok {
		r.manifests[manifestId] = &jsonreportspec.PackageManifestReport{
			Id:        manifestId,
			Path:      manifest.GetPath(),
			Ecosystem: manifest.GetSpecEcosystem(),
		}
	}

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(p *models.Package) error {
		pkgId := p.Id()
		if _, ok := r.packages[pkgId]; !ok {
			r.packages[pkgId] = r.buildJsonPackageReportFromPackage(p)
		}

		if !slices.Contains(r.packages[pkgId].Manifests, manifestId) {
			r.packages[pkgId].Manifests = append(r.packages[p.Id()].Manifests, manifestId)
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
		logger.Warnf("Analyzer event with nil package")
		return
	}

	if event.Package.Manifest == nil {
		logger.Warnf("Analyzer event with nil package manifest")
		return
	}

	if event.Filter == nil {
		logger.Warnf("Analyzer event that matched filter but without Filter object")
		return
	}

	pkgId := event.Package.Id()
	if _, ok := r.packages[pkgId]; !ok {
		r.packages[pkgId] = r.buildJsonPackageReportFromPackage(event.Package)
	}

	// We avoid duplicate violation for a package. Duplicates can occur because same package
	// is in multiple manifests hence raising same violation
	v := utils.FindAnyWith(r.packages[pkgId].Violations, func(item **violations.Violation) bool {
		return ((*item).GetFilter().GetName() == event.Filter.GetName())
	})
	if v != nil {
		return
	}

	// Fall through here to associate a Violation and a RemediationAdvice
	violation := &violations.Violation{
		CheckType: event.Filter.GetCheckType(),
		Filter:    event.Filter,
	}

	r.packages[pkgId].Violations = append(r.packages[pkgId].Violations, violation)

	advice, err := r.remediations.Advice(event.Package, violation)
	if err != nil {
		logger.Warnf("Failed to generate remediation for %s due to %v",
			event.Package.ShortName(), err)
	} else {
		r.packages[pkgId].Advices = append(r.packages[pkgId].Advices, advice)
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

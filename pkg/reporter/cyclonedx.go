package reporter

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/safedep/dry/utils"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils/regex"
	sbomUtils "github.com/safedep/vet/pkg/common/utils/sbom"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
)

// CycloneDXReporterConfig contains configuration parameters for the CycloneDX reporter
type CycloneDXReporterConfig struct {
	Tool ToolMetadata

	// Path defines the output file path
	Path string

	// Application component name, this is the top-level component in the BOM
	ApplicationComponentName string

	// Unique identifier for this BOM confirming to UUID RFC 4122 standard
	// If empty, a new UUID will be generated
	SerialNumber string
}

type cycloneDXReporter struct {
	sync.Mutex
	config                    CycloneDXReporterConfig
	bom                       *cdx.BOM
	toolComponent             cdx.Component
	rootComponentBomref       string
	bomEcosystems             map[string]bool
	bomVulnerabilitiesBomrefs map[string]bool
	bomPackageRef             map[string]bool
}

var cdxUUIDRegexp = regex.MustCompileAndCache(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func NewCycloneDXReporter(config CycloneDXReporterConfig) (Reporter, error) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6

	// Set serial number if provided, otherwise generate a RFC 4122 UUID
	if utils.IsEmptyString(config.SerialNumber) {
		generatedSerialNumber, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID for CycloneDX serial number: %v", err)
		}

		bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", generatedSerialNumber.String())
	} else {
		if !cdxUUIDRegexp.MatchString(config.SerialNumber) {
			return nil, fmt.Errorf("serial number '%s' does not match RFC 4122 UUID format", config.SerialNumber)
		}

		bom.SerialNumber = config.SerialNumber
	}

	toolComponent := cdx.Component{
		Type: cdx.ComponentTypeApplication,
		Manufacturer: &cdx.OrganizationalEntity{
			Name: config.Tool.VendorName,
			URL:  utils.PtrTo([]string{config.Tool.VendorInformationURI}),
		},
		Group:      config.Tool.VendorName,
		Name:       config.Tool.Name,
		Version:    config.Tool.Version,
		PackageURL: config.Tool.Purl,
		BOMRef:     config.Tool.Purl,
	}

	rootComponentBomref := "root-application"
	bom.Metadata = &cdx.Metadata{
		// Define metadata about the main component (the root component which BOM describes)
		Component: &cdx.Component{
			BOMRef:     rootComponentBomref,
			Type:       cdx.ComponentTypeApplication,
			Name:       config.ApplicationComponentName,
			Components: utils.PtrTo([]cdx.Component{}),
		},
		Tools: &cdx.ToolsChoice{
			Components: utils.PtrTo([]cdx.Component{
				toolComponent,
			}),
		},
	}

	bom.Components = utils.PtrTo([]cdx.Component{})
	bom.Vulnerabilities = utils.PtrTo([]cdx.Vulnerability{})
	bom.Dependencies = utils.PtrTo([]cdx.Dependency{})

	return &cycloneDXReporter{
		config:                    config,
		bom:                       bom,
		toolComponent:             toolComponent,
		rootComponentBomref:       rootComponentBomref,
		bomEcosystems:             map[string]bool{},
		bomVulnerabilitiesBomrefs: map[string]bool{},
		bomPackageRef:             map[string]bool{},
	}, nil
}

func (r *cycloneDXReporter) Name() string {
	return "CycloneDX Reporter"
}

func (r *cycloneDXReporter) AddManifest(manifest *models.PackageManifest) {
	r.Lock()
	defer r.Unlock()

	r.bomEcosystems[manifest.Ecosystem] = true

	r.bom.Metadata.Component.Components = utils.PtrTo(append(*r.bom.Metadata.Component.Components, cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		Group:  manifest.Ecosystem,
		BOMRef: manifest.Source.GetPath(),
		Name:   manifest.GetPath(),
		// Version: ,	// @TODO - Introduce manifest.GetVersion()   this is possible in some manifests like package.json, pyproject.toml etc
	}))

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		// If package already visited, skip adding it
		if r.bomPackageRef[pkg.GetPackageUrl()] {
			return nil
		}

		r.addPackage(pkg)

		r.bomPackageRef[pkg.GetPackageUrl()] = true
		return nil
	})
	if err != nil {
		logger.Errorf("[CycloneDX Reporter]: Failed to enumerate packages in manifest %s: %v",
			manifest.GetPath(), err)
	}
}

func (r *cycloneDXReporter) addPackage(pkg *models.Package) {
	pkgPurl := pkg.GetPackageUrl()

	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.GetName(),
		Version:    pkg.GetVersion(),
		PackageURL: pkgPurl,
		BOMRef:     pkgPurl,
		Licenses:   utils.PtrTo(cdx.Licenses(r.resolvePackageLicenses(pkg))),
		Evidence: &cdx.Evidence{
			Identity: utils.PtrTo([]cdx.EvidenceIdentity{
				{
					Field:      cdx.EvidenceIdentityFieldTypePURL,
					Confidence: utils.PtrTo(float32(0.7)),
					Methods: utils.PtrTo([]cdx.EvidenceIdentityMethod{
						{
							Technique:  cdx.EvidenceIdentityTechniqueManifestAnalysis,
							Confidence: utils.PtrTo(float32(0.7)),
							Value:      pkg.Manifest.GetSource().GetPath(),
						},
					}),
				},
			}),
		},
	}

	if pkg.Manifest != nil {
		component.Group = pkg.Manifest.Ecosystem
	}

	r.recordDependencies(pkg)
	r.recordVulnerabilities(pkg)
	r.recordMalware(pkg)

	*r.bom.Components = append(*r.bom.Components, component)
}

func (r *cycloneDXReporter) resolvePackageLicenses(pkg *models.Package) []cdx.LicenseChoice {
	licenses := []cdx.LicenseChoice{}

	if pkg.Insights == nil || pkg.Insights.Licenses == nil {
		return licenses
	}
	for _, license := range *pkg.Insights.Licenses {
		licenseChoice := cdx.LicenseChoice{
			License: &cdx.License{
				ID: string(license),
			},
		}
		licenses = append(licenses, licenseChoice)
	}

	return licenses
}

func (r *cycloneDXReporter) recordDependencies(pkg *models.Package) {
	pkgPurl := pkg.GetPackageUrl()

	deps, err := pkg.GetDependencies()
	if err != nil {
		logger.Errorf("[CycloneDX Reporter]: Failed to get dependencies for package %s: %v", pkgPurl, err)
		return
	}

	depsPurls := []string{}
	for _, dep := range deps {
		depsPurls = append(depsPurls, dep.GetPackageUrl())
	}

	*r.bom.Dependencies = append(*r.bom.Dependencies, cdx.Dependency{
		Ref:          pkgPurl,
		Dependencies: &depsPurls,
	})
}

func (r *cycloneDXReporter) recordVulnerabilities(pkg *models.Package) {
	if pkg.Insights == nil || pkg.Insights.Vulnerabilities == nil {
		return
	}

	pkgPurl := pkg.GetPackageUrl()

	for _, vuln := range *pkg.Insights.Vulnerabilities {
		// This format of Vulnerability BOMRef is used by cdxgen
		vulnBomref := strings.Join([]string{utils.SafelyGetValue(vuln.Id), pkgPurl}, "/")

		if _, ok := r.bomVulnerabilitiesBomrefs[vulnBomref]; ok {
			// This vulnerability has already been recorded
			continue
		}

		ratings := []cdx.VulnerabilityRating{}
		for _, severity := range utils.SafelyGetValue(vuln.Severities) {
			ratingMethod := cdx.ScoringMethodOther
			switch utils.SafelyGetValue(severity.Type) {
			case insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2:
				ratingMethod = cdx.ScoringMethodCVSSv2
			case insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3:
				ratingMethod = cdx.ScoringMethodCVSSv3
			case insightapi.PackageVulnerabilitySeveritiesTypeUNSPECIFIED:
				ratingMethod = cdx.ScoringMethodOther
			}

			rating := cdx.VulnerabilityRating{
				Method:   ratingMethod,
				Severity: cdx.Severity(strings.ToLower(string(utils.SafelyGetValue(severity.Risk)))),
				Vector:   utils.SafelyGetValue(severity.Score),
			}
			calculatedScore, err := sbomUtils.CalculateCvssScore(utils.SafelyGetValue(severity.Score))
			if err == nil {
				rating.Score = &calculatedScore
			}
			ratings = append(ratings, rating)
		}

		recommendation := ""
		if pkg.Insights.PackageCurrentVersion != nil {
			recommendation = fmt.Sprintf("Upgrade to version %s or later", utils.SafelyGetValue(pkg.Insights.PackageCurrentVersion))
		}

		*r.bom.Vulnerabilities = append(*r.bom.Vulnerabilities, cdx.Vulnerability{
			ID:             utils.SafelyGetValue(vuln.Id),
			BOMRef:         vulnBomref,
			Description:    utils.SafelyGetValue(vuln.Summary),
			Ratings:        &ratings,
			Recommendation: recommendation,
			Affects: utils.PtrTo([]cdx.Affects{
				{
					Ref: pkgPurl,
				},
			}),
		})

		r.bomVulnerabilitiesBomrefs[vulnBomref] = true
	}
}

func (r *cycloneDXReporter) recordMalware(pkg *models.Package) {
	if pkg.MalwareAnalysis == nil {
		return
	}

	pkgPurl := pkg.GetPackageUrl()
	malwareAnalysis := utils.SafelyGetValue(pkg.MalwareAnalysis)

	if malwareAnalysis.IsMalware {
		malwareBomref := strings.Join([]string{malwareAnalysis.Id(), pkgPurl}, "/")

		if _, ok := r.bomVulnerabilitiesBomrefs[malwareBomref]; ok {
			// This malware analysis has already been recorded
			return
		}

		inference := utils.SafelyGetValue(malwareAnalysis.Report.GetInference())
		malwareSummary := inference.GetSummary()
		if utils.IsEmptyString(malwareSummary) {
			malwareSummary = fmt.Sprintf("Malicious code in %s (%s)", pkg.GetName(), pkg.Ecosystem)
		}

		*r.bom.Vulnerabilities = append(*r.bom.Vulnerabilities, cdx.Vulnerability{
			ID:          malwareAnalysis.Id(),
			BOMRef:      malwareBomref,
			Description: malwareSummary,
			Credits: &cdx.Credits{
				Organizations: utils.PtrTo([]cdx.OrganizationalEntity{
					{
						BOMRef: r.config.Tool.VendorName,
						Name:   r.config.Tool.VendorName,
						URL:    utils.PtrTo([]string{r.config.Tool.VendorInformationURI}),
					},
				}),
			},
			Properties: utils.PtrTo([]cdx.Property{
				{
					Name:  "report-url",
					Value: malysis.ReportURL(malwareAnalysis.AnalysisId),
				},
			}),
			Source: &cdx.Source{
				Name: r.config.Tool.Name,
				URL:  r.config.Tool.InformationURI,
			},
			Affects: utils.PtrTo([]cdx.Affects{
				{
					Ref: pkgPurl,
				},
			}),
		})

		r.bomVulnerabilitiesBomrefs[malwareBomref] = true
	}
}

func (r *cycloneDXReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
}

func (r *cycloneDXReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *cycloneDXReporter) finaliseBom() {
	bomGenerationTime := time.Now().UTC()

	r.bom.Metadata.Timestamp = bomGenerationTime.Format(time.RFC3339)

	r.bom.Annotations = utils.PtrTo([]cdx.Annotation{
		{
			BOMRef: "metadata-annotations",
			Subjects: utils.PtrTo([]cdx.BOMReference{
				cdx.BOMReference(r.rootComponentBomref),
			}),
			Annotator: &cdx.Annotator{
				Component: &r.toolComponent,
			},
			Timestamp: bomGenerationTime.Format(time.RFC3339),
			Text:      fmt.Sprintf("This Software Bill-of-Materials (SBOM) document was created on %s with %s. The data was captured during the build lifecycle phase. The document describes '%s'. It has total %d components. %d ecosystems are described in the document under components.", bomGenerationTime.Format("Monday, January 2, 2006"), r.config.Tool.Name, r.config.ApplicationComponentName, len(*r.bom.Components), len(r.bomEcosystems)),
		},
	})
}

func (r *cycloneDXReporter) Finish() error {
	r.finaliseBom()

	logger.Infof("Writing CycloneDX report to %s", r.config.Path)

	fd, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}
	defer fd.Close()

	err = cdx.NewBOMEncoder(fd, cdx.BOMFileFormatJSON).
		SetPretty(true).
		Encode(r.bom)
	if err != nil {
		return err
	}

	return nil
}

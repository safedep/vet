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
	commonUtils "github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/common/utils/regex"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter/data"
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
	config        CycloneDXReporterConfig
	bom           *cdx.BOM
	toolComponent cdx.Component
	bomPurls      map[string]bool
	bomEcosystems map[string]bool
}

var cdxUUIDRegexp = regex.MustCompileAndCache(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func NewCycloneDXReporter(config CycloneDXReporterConfig) (Reporter, error) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6

	// Set serial number if provided, otherwise generate a RFC 4122 UUID
	if utils.IsEmptyString(config.SerialNumber) {
		generatedSerialNumber, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("Failed to generate UUID for CycloneDX serial number: %v", err)
		}

		bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", generatedSerialNumber.String())
	} else {
		if !cdxUUIDRegexp.MatchString(config.SerialNumber) {
			return nil, fmt.Errorf("Serial number '%s' does not match RFC 4122 UUID format", config.SerialNumber)
		}

		bom.SerialNumber = config.SerialNumber
	}

	toolComponent := cdx.Component{
		Type: cdx.ComponentTypeApplication,
		Manufacturer: &cdx.OrganizationalEntity{
			Name: config.Tool.VendorName,
			URL:  commonUtils.PtrTo([]string{config.Tool.VendorInformationURI}),
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
			Components: commonUtils.PtrTo([]cdx.Component{}),
		},
		Tools: &cdx.ToolsChoice{
			Components: commonUtils.PtrTo([]cdx.Component{
				toolComponent,
			}),
		},
	}

	bom.Annotations = commonUtils.PtrTo([]cdx.Annotation{
		{
			BOMRef: "metadata-annotations",
			Subjects: commonUtils.PtrTo([]cdx.BOMReference{
				cdx.BOMReference(rootComponentBomref),
			}),
			Annotator: &cdx.Annotator{
				Component: &toolComponent,
			},
		},
	})

	bom.Components = commonUtils.PtrTo([]cdx.Component{})
	bom.Vulnerabilities = commonUtils.PtrTo([]cdx.Vulnerability{})
	bom.Dependencies = commonUtils.PtrTo([]cdx.Dependency{})

	return &cycloneDXReporter{
		config:        config,
		bom:           bom,
		toolComponent: toolComponent,
		bomPurls:      map[string]bool{},
		bomEcosystems: map[string]bool{},
	}, nil
}

func (r *cycloneDXReporter) Name() string {
	return "CycloneDX Reporter"
}

func (r *cycloneDXReporter) AddManifest(manifest *models.PackageManifest) {
	r.Lock()
	defer r.Unlock()

	r.bomEcosystems[manifest.Ecosystem] = true

	r.bom.Metadata.Component.Components = commonUtils.PtrTo(append(*r.bom.Metadata.Component.Components, cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		Group:  manifest.Ecosystem,
		BOMRef: manifest.Source.GetPath(),
		Name:   manifest.GetPath(),
		// Version: ,	// @TODO - Introduce manifest.GetVersion()   this is possible in some manifests like package.json, pyproject.toml etc
	}))

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		r.addPackage(pkg)
		return nil
	})
	if err != nil {
		logger.Errorf("[CycloneDX Reporter]: Failed to enumerate packages in manifest %s: %v",
			manifest.GetPath(), err)
	}
}

func (r *cycloneDXReporter) addPackage(pkg *models.Package) {
	pkgPurl := pkg.GetPackageUrl()
	r.bomPurls[pkgPurl] = true

	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.GetName(),
		Version:    pkg.GetVersion(),
		PackageURL: pkgPurl,
		BOMRef:     pkgPurl,
		Licenses:   commonUtils.PtrTo(cdx.Licenses(r.resolvePackageLicenses(pkg))),
		Evidence: &cdx.Evidence{
			Identity: commonUtils.PtrTo([]cdx.EvidenceIdentity{
				{
					Field:      cdx.EvidenceIdentityFieldTypePURL,
					Confidence: commonUtils.PtrTo(float32(0.7)),
					Methods: commonUtils.PtrTo([]cdx.EvidenceIdentityMethod{
						{
							Technique:  cdx.EvidenceIdentityTechniqueManifestAnalysis,
							Confidence: commonUtils.PtrTo(float32(0.7)),
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
				Name: string(license),
				ID:   string(license),
			},
		}
		if _, validSpdxLicense := data.SPDXLicenseMap[string(license)]; validSpdxLicense {
			// @TODO - this is taken from https://github.com/CycloneDX/cdxgen/blob/c32b2b64174c190490e34e18fe7c9a3f7bb4904e/lib/helpers/utils.js#L814
			// However, some licenses don't point to a valid URL
			licenseChoice.License.URL = "https://opensource.org/licenses/" + string(license)
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
			ratings = append(ratings, rating)
		}

		*r.bom.Vulnerabilities = append(*r.bom.Vulnerabilities, cdx.Vulnerability{
			ID:          utils.SafelyGetValue(vuln.Id),
			BOMRef:      strings.Join([]string{utils.SafelyGetValue(vuln.Id), pkgPurl}, "/"), // This format of Vulnerability BOMRef is used by cdxgen
			Description: utils.SafelyGetValue(vuln.Summary),
			Ratings:     &ratings,
			Affects: commonUtils.PtrTo([]cdx.Affects{
				{
					Ref: pkgPurl,
				},
			}),
		})
	}
}

func (r *cycloneDXReporter) recordMalware(pkg *models.Package) {
	if pkg.MalwareAnalysis == nil {
		return
	}

	pkgPurl := pkg.GetPackageUrl()
	malwareAnalysis := utils.SafelyGetValue(pkg.MalwareAnalysis)

	if malwareAnalysis.IsMalware {
		inference := utils.SafelyGetValue(malwareAnalysis.Report.GetInference())
		malwareSummary := inference.GetSummary()
		if utils.IsEmptyString(malwareSummary) {
			malwareSummary = fmt.Sprintf("Malicious code in %s (%s)", pkg.GetName(), pkg.Ecosystem)
		}

		*r.bom.Vulnerabilities = append(*r.bom.Vulnerabilities, cdx.Vulnerability{
			ID:          utils.SafelyGetValue(&malwareAnalysis.AnalysisId),
			BOMRef:      strings.Join([]string{malwareAnalysis.AnalysisId, pkgPurl}, "/"), // This format of Vulnerability BOMRef is used by cdxgen
			Description: malwareSummary,
			Credits: &cdx.Credits{
				Organizations: commonUtils.PtrTo([]cdx.OrganizationalEntity{
					{
						BOMRef: r.toolComponent.BOMRef,
						Name:   r.toolComponent.Name,
						URL:    commonUtils.PtrTo([]string{r.config.Tool.InformationURI}),
					},
				}),
			},
			Properties: commonUtils.PtrTo([]cdx.Property{
				{
					Name:  "report-url",
					Value: malysis.ReportURL(malwareAnalysis.AnalysisId),
				},
			}),
			Source: &cdx.Source{
				Name: r.config.Tool.Name,
				URL:  r.config.Tool.InformationURI,
			},
			Affects: commonUtils.PtrTo([]cdx.Affects{
				{
					Ref: pkgPurl,
				},
			}),
		})
	}
}

func (r *cycloneDXReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
}

func (r *cycloneDXReporter) AddPolicyEvent(event *policy.PolicyEvent) {
	// @TODO - How to handle policy events
}

func (r *cycloneDXReporter) finaliseBom() {
	bomGenerationTime := time.Now().UTC()

	r.bom.Metadata.Timestamp = bomGenerationTime.Format(time.RFC3339)

	annotation := (*r.bom.Annotations)[0]
	annotation.Timestamp = bomGenerationTime.Format(time.RFC3339)
	annotation.Text = fmt.Sprintf("This Software Bill-of-Materials (SBOM) document was created on %s with %s. The data was captured during the build lifecycle phase. The document describes '%s'. It has total %d components. %d package type(s) and %d purl namespaces are described in the document under components.", bomGenerationTime.Format("Monday, January 2, 2006"), r.config.Tool.Name, r.config.ApplicationComponentName, len(*r.bom.Components), len(r.bomEcosystems), len(r.bomPurls))

	(*r.bom.Annotations)[0] = annotation
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

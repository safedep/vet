package reporter

import (
	"fmt"
	"os"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	commonUtils "github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/common/utils/regex"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter/data"
)

type CycloneDXToolMetadata struct {
	Name    string
	Version string
	Purl    string
}

// CycloneDXReporterConfig contains configuration parameters for the CycloneDX reporter
type CycloneDXReporterConfig struct {
	Tool CycloneDXToolMetadata

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
	config CycloneDXReporterConfig
	bom    *cdx.BOM
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

	bom.Metadata = &cdx.Metadata{
		// Define metadata about the main component (the root component which BOM describes)
		Component: &cdx.Component{
			BOMRef:     "root-application",
			Type:       cdx.ComponentTypeApplication,
			Name:       config.ApplicationComponentName,
			Components: &[]cdx.Component{},
		},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type: cdx.ComponentTypeApplication,
					Manufacturer: &cdx.OrganizationalEntity{
						Name: "SafeDep",
						URL:  &[]string{"https://safedep.io/"},
					},
					Name:       config.Tool.Name,
					Version:    config.Tool.Version,
					PackageURL: config.Tool.Purl,
					BOMRef:     config.Tool.Purl,
				},
			},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	bom.Components = &[]cdx.Component{}
	bom.Vulnerabilities = &[]cdx.Vulnerability{}
	bom.Dependencies = &[]cdx.Dependency{}

	return &cycloneDXReporter{
		config: config,
		bom:    bom,
	}, nil
}

func (r *cycloneDXReporter) Name() string {
	return "CycloneDX Reporter"
}

func (r *cycloneDXReporter) AddManifest(manifest *models.PackageManifest) {
	r.Lock()
	defer r.Unlock()

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

	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.GetName(),
		Version:    pkg.GetVersion(),
		PackageURL: pkgPurl,
		BOMRef:     pkgPurl,
		Licenses:   &cdx.Licenses{},
		Evidence: &cdx.Evidence{
			Identity: &[]cdx.EvidenceIdentity{
				{
					Field:      cdx.EvidenceIdentityFieldTypePURL,
					Confidence: commonUtils.PtrTo(float32(0.7)),
					Methods: &[]cdx.EvidenceIdentityMethod{
						{
							Technique:  cdx.EvidenceIdentityTechniqueManifestAnalysis,
							Confidence: commonUtils.PtrTo(float32(0.7)),
							Value:      pkg.Manifest.GetSource().GetPath(),
						},
					},
				},
			},
		},
	}

	if pkg.Manifest != nil {
		component.Group = pkg.Manifest.Ecosystem
	}

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

	if pkg.Insights != nil {
		if pkg.Insights.Licenses != nil {
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
				*component.Licenses = append(*component.Licenses, licenseChoice)
			}
		}

		if pkg.Insights.Vulnerabilities != nil {
			for _, vuln := range *pkg.Insights.Vulnerabilities {
				*r.bom.Vulnerabilities = append(*r.bom.Vulnerabilities, cdx.Vulnerability{
					ID:          utils.SafelyGetValue(vuln.Id),
					Description: utils.SafelyGetValue(vuln.Summary),
					Affects: commonUtils.PtrTo([]cdx.Affects{
						{
							Ref: pkgPurl,
						},
					}),
				})
			}
		}
	}

	*r.bom.Components = append(*r.bom.Components, component)
}

func (r *cycloneDXReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
}

func (r *cycloneDXReporter) AddPolicyEvent(event *policy.PolicyEvent) {
	// @TODO - How to handle policy events
}

func (r *cycloneDXReporter) Finish() error {
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

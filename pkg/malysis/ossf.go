package malysis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/safedep/vet/pkg/common/logger"
)

const (
	defaultCreditName = "SafeDep"
	defaultCreditURL  = "https://safedep.io"
)

// Common config for the generator.
type OpenSSFMaliciousPackageReportGeneratorConfig struct {
	// We take a dir as input and generate files following the contributors
	// guidelines in https://github.com/ossf/malicious-packages
	Dir string
}

// Params for generating the report. For example, it can specific version range
// and other details.
type OpenSSFMaliciousPackageReportParams struct {
	FinderName        string
	Contacts          []string
	VersionIntroduced string
	VersionFixed      string
}

type openSSFMaliciousPackageReportGenerator struct {
	config OpenSSFMaliciousPackageReportGeneratorConfig
}

func NewOpenSSFMaliciousPackageReportGenerator(config OpenSSFMaliciousPackageReportGeneratorConfig) (*openSSFMaliciousPackageReportGenerator, error) {
	st, err := os.Stat(config.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat dir: %w", err)
	}

	if !st.IsDir() {
		return nil, fmt.Errorf("dir is not a directory: %s", config.Dir)
	}

	return &openSSFMaliciousPackageReportGenerator{
		config: config,
	}, nil
}

func (g *openSSFMaliciousPackageReportGenerator) GenerateReport(ctx context.Context,
	report *malysisv1pb.Report, params OpenSSFMaliciousPackageReportParams,
) error {
	ecosystem, err := g.ecosystemFor(report.GetPackageVersion().GetPackage().GetEcosystem())
	if err != nil {
		return fmt.Errorf("failed to get ecosystem: %w", err)
	}

	versionIntroduced := params.VersionIntroduced
	if versionIntroduced == "" {
		// Fallback to the special version "0.0.0" which means all versions
		// of the package is likely malicious
		versionIntroduced = "0.0.0"
	}

	finderName := params.FinderName
	if finderName == "" {
		finderName = defaultCreditName
	}

	contacts := params.Contacts
	if len(contacts) == 0 {
		contacts = []string{defaultCreditURL}
	}

	vuln := osvschema.Vulnerability{
		SchemaVersion: osvschema.SchemaVersion,
		Modified:      time.Now(),
		Published:     time.Now(),
		Summary:       fmt.Sprintf("Malicious code in %s package (%s)", report.GetPackageVersion().GetPackage().GetName(), ecosystem),
		Details:       report.GetInference().GetSummary(), // This is intentional to map our summary with OSV details
		References: []osvschema.Reference{
			{
				Type: osvschema.ReferenceReport,
				URL:  ReportURL(report.GetReportId()),
			},
		},
		Credits: []osvschema.Credit{
			{
				Type:    osvschema.CreditFinder,
				Name:    finderName,
				Contact: contacts,
			},
		},
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
					Ecosystem: ecosystem,
					Name:      report.GetPackageVersion().GetPackage().GetName(),
				},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeSemVer,
						Events: []osvschema.Event{
							{
								Introduced: versionIntroduced,
								Fixed:      params.VersionFixed,
							},
						},
					},
				},
			},
		},
	}

	relFilePath, err := g.relativeFilePath(report.GetPackageVersion().GetPackage().GetEcosystem(),
		report.GetPackageVersion().GetPackage().GetName())
	if err != nil {
		return fmt.Errorf("failed to get relative file path: %w", err)
	}

	json, err := json.MarshalIndent(vuln, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability: %w", err)
	}

	fullFilePath := filepath.Join(g.config.Dir, relFilePath)
	err = os.MkdirAll(filepath.Dir(fullFilePath), 0o755)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	logger.Debugf("Writing OSV report to: %s", fullFilePath)

	err = os.WriteFile(fullFilePath, json, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write vulnerability: %w", err)
	}

	return nil
}

var maliciousPackagesEcosystemMap = map[packagev1.Ecosystem]string{
	packagev1.Ecosystem_ECOSYSTEM_NPM:      "npm",
	packagev1.Ecosystem_ECOSYSTEM_PYPI:     "pypi",
	packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS: "rubygems",
	packagev1.Ecosystem_ECOSYSTEM_GO:       "go",
	packagev1.Ecosystem_ECOSYSTEM_MAVEN:    "maven",
	packagev1.Ecosystem_ECOSYSTEM_CARGO:    "crates-io",
}

func (g *openSSFMaliciousPackageReportGenerator) ecosystemFor(ecosystem packagev1.Ecosystem) (string, error) {
	ecosystemStr, ok := maliciousPackagesEcosystemMap[ecosystem]
	if !ok {
		return "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}

	return ecosystemStr, nil
}

// Generate relative file path for the report based on package ecosystem
// and conventions followed in https://github.com/ossf/malicious-packages
func (g *openSSFMaliciousPackageReportGenerator) relativeFilePath(ecosystem packagev1.Ecosystem, packageName string) (string, error) {
	ecosystemStr, ok := maliciousPackagesEcosystemMap[ecosystem]
	if !ok {
		return "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}

	prefix := "osv/malicious"

	// Fixup package names. This has its own ecosystem specific rules.
	packageFileName := strings.ReplaceAll(packageName, "/", "-")
	packageFileName = strings.ReplaceAll(packageFileName, ":", "-")

	switch ecosystemStr {
	case "npm":
		return fmt.Sprintf("%s/npm/%s/MAL-0000-%s.json", prefix, packageName, packageFileName), nil
	case "pypi":
		return fmt.Sprintf("%s/pypi/%s/MAL-0000-%s.json", prefix, packageName, packageFileName), nil
	case "rubygems":
		return fmt.Sprintf("%s/rubygems/%s/MAL-0000-%s.json", prefix, packageName, packageFileName), nil
	case "go":
		return fmt.Sprintf("%s/go/%s/MAL-0000-%s.json", prefix, packageName, packageFileName), nil
	case "maven":
		return fmt.Sprintf("%s/maven/%s/MAL-0000-%s.json", prefix, packageName, packageFileName), nil
	case "crates-io":
		return fmt.Sprintf("%s/crates-io/%s/MAL-0000-%s.json", prefix, packageName, packageFileName), nil
	default:
		return "", fmt.Errorf("unsupported ecosystem: %s", ecosystemStr)
	}
}

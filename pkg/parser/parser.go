package parser

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"

	cdx "github.com/safedep/vet/pkg/parser/custom/cyclonedx_sbom"
	"github.com/safedep/vet/pkg/parser/custom/py"
	spdx "github.com/safedep/vet/pkg/parser/custom/spdx_sbom"
)

const (
	customParserTypePyWheel   = "python-wheel"
	customParserCycloneDXSBOM = "bom-cyclonedx"
	customParserSpdxSBOM      = "bom-spdx"
	customParserTypeSetupPy   = "setup.py"
)

// Exporting as constants for use outside this package to refer to specific
// parsers. For example: Github reader
const (
	LockfileAsBomSpdx      = customParserSpdxSBOM
	LockfileAsBomCycloneDx = customParserCycloneDXSBOM
)

// We are supporting only those ecosystems for which we have data
// for enrichment. More ecosystems will be supported as we improve
// the capability of our Insights API
var supportedEcosystems map[string]bool = map[string]bool{
	models.EcosystemGo:       true,
	models.EcosystemMaven:    true,
	models.EcosystemNpm:      true,
	models.EcosystemPyPI:     true,
	models.EcosystemCyDxSBOM: true,
	models.EcosystemSpdxSBOM: true,
}

var customExperimentalParsers map[string]lockfile.PackageDetailsParser = map[string]lockfile.PackageDetailsParser{
	customParserTypePyWheel:   parsePythonWheelDist,
	customParserCycloneDXSBOM: cdx.Parse,
	customParserSpdxSBOM:      spdx.Parse,
	customParserTypeSetupPy:   py.ParseSetuppy,
}

type Parser interface {
	Ecosystem() string
	Parse(lockfilePath string) (models.PackageManifest, error)
}

type parserWrapper struct {
	parser  lockfile.PackageDetailsParser
	parseAs string
}

func List(experimental bool) []string {
	supportedParsers := make([]string, 0, 0)
	parsers := lockfile.ListParsers()

	for _, p := range parsers {
		_, err := FindParser("", p)
		if err != nil {
			continue
		}

		supportedParsers = append(supportedParsers, p)
	}

	if experimental {
		for p := range customExperimentalParsers {
			supportedParsers = append(supportedParsers, p)
		}
	}

	return supportedParsers
}

func FindParser(lockfilePath, lockfileAs string) (Parser, error) {
	p, pa := lockfile.FindParser(lockfilePath, lockfileAs)
	if p != nil {
		pw := &parserWrapper{parser: p, parseAs: pa}
		if pw.supported() {
			return pw, nil
		}
	}

	logger.Debugf("Trying to find parser in experimental parsers %s", lockfileAs)
	if p, ok := customExperimentalParsers[lockfileAs]; ok {
		pw := &parserWrapper{parser: p, parseAs: lockfileAs}
		if pw.supported() {
			logger.Debugf("Found Parser type for the type %s", lockfileAs)
			return pw, nil
		}
	}

	logger.Debugf("No Parser found for the type %s", lockfileAs)
	return nil, fmt.Errorf("no parser found with: %s for: %s", lockfileAs,
		lockfilePath)
}

func (pw *parserWrapper) supported() bool {
	return supportedEcosystems[pw.Ecosystem()]
}

func (pw *parserWrapper) Ecosystem() string {
	logger.Debugf("Provided Lockfile Type %s", pw.parseAs)
	switch pw.parseAs {
	case "Cargo.lock":
		return models.EcosystemCargo
	case "composer.lock":
		return models.EcosystemPackagist
	case "Gemfile.lock":
		return models.EcosystemRubyGems
	case "go.mod":
		return models.EcosystemGo
	case "mix.lock":
		return models.EcosystemHex
	case "package-lock.json":
		return models.EcosystemNpm
	case "pnpm-lock.yaml":
		return models.EcosystemNpm
	case "poetry.lock":
		return models.EcosystemPyPI
	case "pom.xml":
		return models.EcosystemMaven
	case "pubspec.lock":
		return models.EcosystemPub
	case "requirements.txt":
		return models.EcosystemPyPI
	case "Pipfile.lock":
		return models.EcosystemPyPI
	case "yarn.lock":
		return models.EcosystemNpm
	case "gradle.lockfile":
		return models.EcosystemMaven
	case "buildscript-gradle.lockfile":
		return models.EcosystemMaven
	case customParserTypePyWheel:
		return models.EcosystemPyPI
	case customParserCycloneDXSBOM:
		return models.EcosystemCyDxSBOM
	case customParserTypeSetupPy:
		return models.EcosystemPyPI
	case customParserSpdxSBOM:
		return models.EcosystemSpdxSBOM
	default:
		logger.Debugf("Unsupported lockfile-as %s", pw.parseAs)
		return ""
	}
}

func (pw *parserWrapper) Parse(lockfilePath string) (models.PackageManifest, error) {
	pm := models.PackageManifest{Path: lockfilePath,
		Ecosystem: pw.Ecosystem()}

	logger.Infof("[%s] Parsing %s", pw.parseAs, lockfilePath)

	packages, err := pw.parser(lockfilePath)
	if err != nil {
		return pm, err
	}

	for _, pkg := range packages {
		pm.AddPackage(&models.Package{
			PackageDetails: pkg,
			Manifest:       &pm,
		})
	}

	return pm, nil
}

package parser

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"

	"github.com/safedep/vet/pkg/parser/custom/py"
	"github.com/safedep/vet/pkg/parser/custom/sbom/spdx"
)

const (
	customParserTypePyWheel           = "python-wheel"
	customParserCycloneDXSBOM         = "bom-cyclonedx"
	customParserSpdxSBOM              = "bom-spdx"
	customParserTypeSetupPy           = "setup.py"
	customParserTypeJavaArchive       = "jar"
	customParserTypeJavaWebAppArchive = "war"
	customParserGitHubActions         = "github-actions"
	customParserTerraform             = "terraform"
)

var (
	errUnsupportedFormat = errors.New("unsupported format")
)

// Exporting as constants for use outside this package to refer to specific
// parsers. For example: Github reader
const (
	LockfileAsBomSpdx       = customParserSpdxSBOM
	LockfileAsBomCycloneDx  = customParserCycloneDXSBOM
	LockfileAsGitHubActions = customParserGitHubActions
)

// We are supporting only those ecosystems for which we have data
// for enrichment. More ecosystems will be supported as we improve
// the capability of our Insights API
var supportedEcosystems map[string]bool = map[string]bool{
	models.EcosystemGo:            true,
	models.EcosystemMaven:         true,
	models.EcosystemNpm:           true,
	models.EcosystemPyPI:          true,
	models.EcosystemRubyGems:      true,
	models.EcosystemPackagist:     true,
	models.EcosystemCyDxSBOM:      true,
	models.EcosystemSpdxSBOM:      true,
	models.EcosystemGitHubActions: true,
	models.EcosystemTerraform:     true,
}

// TODO: Migrate these to graph parser
var customExperimentalParsers map[string]lockfile.PackageDetailsParser = map[string]lockfile.PackageDetailsParser{
	customParserTypePyWheel: parsePythonWheelDist,
	customParserSpdxSBOM:    spdx.Parse,
	customParserTypeSetupPy: py.ParseSetuppy,
}

type Parser interface {
	Ecosystem() string
	Parse(lockfilePath string) (*models.PackageManifest, error)
	ParseWithConfig(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error)
}

type ParserConfig struct {
	// A generic config flag (not specific to npm even though the name sounds like that) to indicate
	// if the parser should include non-production dependencies as well. But this will work
	// only for supported parsers such as npm graph parser
	IncludeDevDependencies bool
}

// Graph parser always takes precedence over lockfile parser
type parserWrapper struct {
	graphParser dependencyGraphParser
	parser      lockfile.PackageDetailsParser
	parseAs     string
}

// This is how a graph parser should be implemented
type dependencyGraphParser func(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error)

// Maintain a map of lockfileAs to dependencyGraphParser
var dependencyGraphParsers map[string]dependencyGraphParser = map[string]dependencyGraphParser{
	"package.json":                    parseNpmPackageJsonAsGraph,
	"package-lock.json":               parseNpmPackageLockAsGraph,
	customParserCycloneDXSBOM:         parseSbomCycloneDxAsGraph,
	customParserTypeJavaArchive:       parseJavaArchiveAsGraph,
	customParserTypeJavaWebAppArchive: parseJavaArchiveAsGraph,
	customParserGitHubActions:         parseGithubActionWorkflowAsGraph,
	customParserTerraform:             parseTerraformLockfile,
}

// Maintain a map of extension to lockfileAs
// Ensure that only supported extensions are added
var lockfileAsMapByExtension map[string]string = map[string]string{
	"jar": customParserTypeJavaArchive,
	"war": customParserTypeJavaWebAppArchive,
}

// Maintain a map of standard filenames to a custom parser. This has
// higher precendence that lockfile package. Graph parsers discover
// reference to this map to resolve the lockfileAs from base filename
var lockfileAsMapByPath map[string]string = map[string]string{
	".terraform.lock.hcl": customParserTerraform,
}

func FindLockFileAsByExtension(extension string) (string, error) {
	if lockfileAs, ok := lockfileAsMapByExtension[extension]; ok {
		return lockfileAs, nil
	}

	return "", fmt.Errorf("no format found for the extension %s", extension)
}

func List(experimental bool) []string {
	supportedParsers := make([]string, 0, 0)

	for pa := range dependencyGraphParsers {
		supportedParsers = append(supportedParsers, fmt.Sprintf("%s (graph)", pa))
	}

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
	// Find a graph parser for the lockfile
	logger.Debugf("Trying to find graph parser for %s", lockfilePath)
	gp, gpa := findGraphParser(lockfilePath, lockfileAs)
	if gp != nil {
		pw := &parserWrapper{graphParser: gp, parseAs: gpa}
		if pw.supported() {
			return pw, nil
		}
	}

	// Try to find a parser for the lockfile
	logger.Debugf("Trying to find lockfile parser for %s", lockfilePath)
	p, pa := lockfile.FindParser(lockfilePath, lockfileAs)
	if p != nil {
		pw := &parserWrapper{parser: p, parseAs: pa}
		if pw.supported() {
			return pw, nil
		}
	}

	// Use experimental parser for explicitly provided lockfile type
	logger.Debugf("Trying to find parser in experimental parsers %s", lockfileAs)
	if p, ok := customExperimentalParsers[lockfileAs]; ok {
		pw := &parserWrapper{parser: p, parseAs: lockfileAs}
		if pw.supported() {
			logger.Debugf("Found Parser type for the type %s", lockfileAs)
			return pw, nil
		}

	}

	// Check special case of GitHub actions
	if m, err := regexp.Match(`\.github/(workflows|actions)/.*\.(yml|yaml)`, []byte(lockfilePath)); m && err == nil {
		pw := &parserWrapper{graphParser: parseGithubActionWorkflowAsGraph,
			parseAs: customParserGitHubActions}
		if pw.supported() {
			return pw, nil
		}
	}

	// We failed!
	logger.Debugf("No Parser found for the type %s", lockfileAs)
	return nil, fmt.Errorf("no parser found with: %s for: %s", lockfileAs,
		lockfilePath)
}

func findGraphParser(lockfilePath, lockfileAs string) (dependencyGraphParser, string) {
	parseAs := lockfileAs
	if lockfileAs == "" {
		parseAs = filepath.Base(lockfilePath)
		if _, ok := lockfileAsMapByPath[parseAs]; ok {
			parseAs = lockfileAsMapByPath[parseAs]
		}
	}

	if _, ok := dependencyGraphParsers[parseAs]; ok {
		return dependencyGraphParsers[parseAs], parseAs
	}

	return nil, ""
}

func (pw *parserWrapper) supported() bool {
	return supportedEcosystems[pw.Ecosystem()]
}

func (pw *parserWrapper) Ecosystem() string {
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
	case "package.json":
		return models.EcosystemNpm
	case customParserTypePyWheel:
		return models.EcosystemPyPI
	case customParserCycloneDXSBOM:
		return models.EcosystemCyDxSBOM
	case customParserTypeSetupPy:
		return models.EcosystemPyPI
	case customParserSpdxSBOM:
		return models.EcosystemSpdxSBOM
	case customParserTypeJavaArchive:
		return models.EcosystemMaven
	case customParserTypeJavaWebAppArchive:
		return models.EcosystemMaven
	case customParserGitHubActions:
		return models.EcosystemGitHubActions
	case customParserTerraform:
		return models.EcosystemTerraform
	default:
		logger.Debugf("Unsupported lockfile-as %s", pw.parseAs)
		return ""
	}
}

func (pw *parserWrapper) Parse(lockfilePath string) (*models.PackageManifest, error) {
	return pw.ParseWithConfig(lockfilePath, &ParserConfig{
		IncludeDevDependencies: true,
	})
}

func (pw *parserWrapper) ParseWithConfig(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error) {
	logger.Infof("[%s] Parsing %s", pw.parseAs, lockfilePath)
	if pw.graphParser != nil {
		return pw.graphParser(lockfilePath, config)
	}

	packages, err := pw.parser(lockfilePath)
	if err != nil {
		return nil, err
	}

	pm := models.NewPackageManifestFromLocal(lockfilePath, pw.Ecosystem())
	for _, pkg := range packages {
		pm.AddPackage(&models.Package{
			PackageDetails: pkg,
			Manifest:       pm,
		})
	}

	return pm, nil
}

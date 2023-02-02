package parser

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

// We are supporting only those ecosystems for which we have data
// for enrichment. More ecosystems will be supported as we improve
// the capability of our Insights API
var supportedEcosystems map[string]bool = map[string]bool{
	models.EcosystemGo:    true,
	models.EcosystemMaven: true,
	models.EcosystemNpm:   true,
	models.EcosystemPyPI:  true,
}

type Parser interface {
	Ecosystem() string
	Parse(lockfilePath string) (models.PackageManifest, error)
}

type parserWrapper struct {
	parser  lockfile.PackageDetailsParser
	parseAs string
}

func List() []string {
	supportedParsers := make([]string, 0, 0)
	parsers := lockfile.ListParsers()

	for _, p := range parsers {
		_, err := FindParser("", p)
		if err != nil {
			continue
		}

		supportedParsers = append(supportedParsers, p)
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

	return nil, fmt.Errorf("no parser found with: %s for: %s", lockfileAs,
		lockfilePath)
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
	case "yarn.lock":
		return models.EcosystemNpm
	case "gradle.lockfile":
		return models.EcosystemMaven
	case "buildscript-gradle.lockfile":
		return models.EcosystemMaven
	default:
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

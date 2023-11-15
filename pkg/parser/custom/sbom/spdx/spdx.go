package spdx

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
	sbom_utils "github.com/safedep/vet/pkg/common/utils/sbom"
	"github.com/safedep/vet/pkg/parser/custom/packagefile"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_go "github.com/spdx/tools-golang/spdx"
)

/*
Parse spdx sbom file and convert into Package Detailss
*/
func Parse(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	logger.Debugf("Starting SBOM decoding...")
	details := make([]lockfile.PackageDetails, 0)

	pd_doc, err := parse2PackageDetailsDoc(pathToLockfile)
	if err != nil {
		return details, err
	}
	// Convert PackageDetails Doc to lockfile.PackageDetail
	for _, pd := range pd_doc.PackageDetails {
		lockfile_pd := pd.Convert2LockfilePackageDetails()
		details = append(details, *lockfile_pd)
	}
	logger.Debugf("Found number of packages %d", len(details))
	return details, nil
}

/*
Parse and create PackageDetailsDoc
*/
func parse2PackageDetailsDoc(pathToLockfile string) (*packagefile.PackageDetailsDoc, error) {
	r, err := os.Open(pathToLockfile)
	if err != nil {
		logger.Debugf("Error while opening %v for reading: %v", pathToLockfile, err)
		return nil, err
	}

	defer r.Close()

	bom, err := spdx_json.Read(r)
	if err != nil {
		logger.Debugf("Error while parsing %v: %v", pathToLockfile, err)
		return nil, err
	}

	details := &packagefile.PackageDetailsDoc{
		SpdxDoc:        bom,
		SourceType:     packagefile.SPDX_SRC_TYPE,
		PackageDetails: make([]*packagefile.PackageDetails, 0),
	}

	// Components is a pointer array and it can be empty
	if bom.Packages != nil {
		for _, comp := range bom.Packages {
			// Skip for the package details same as parent library
			if comp.PackageName == bom.DocumentName {
				continue
			}

			pd, err := parsePackage(comp)
			if err != nil {
				logger.Debugf("Error while parsing the spdx pkg %s %v", comp.PackageName, err)
				continue
			}

			details.PackageDetails = append(details.PackageDetails, pd)
		}
	}

	return details, nil
}

func parsePackage(pkg *spdx_go.Package) (*packagefile.PackageDetails, error) {
	pd, _ := parsePackageFromPurl(pkg)
	if pd != nil {
		return pd, nil
	}

	pd, err := parsePackageFromPackageDetails(pkg)
	return pd, err
}

// Parse from Purl if available. It is a reliable parsing technique
func parsePackageFromPurl(pkg *spdx_go.Package) (*packagefile.PackageDetails, error) {
	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == "purl" {
			pd, err := packagefile.ParsePackageFromPurl(ref.Locator)
			if pd != nil {
				pd.SpdxRef = pkg
			}

			return pd, err
		}
	}

	return nil, nil
}

// Parse from package details, if available. It is bit Unreliable Parsing
func parsePackageFromPackageDetails(pkg *spdx_go.Package) (*packagefile.PackageDetails, error) {
	ptype, g, n, ok := attempParsePackageName(pkg.PackageName)

	// FIXME: Generalize this
	if strings.HasPrefix(ptype, "maven:") {
		parts := strings.Split(ptype, ":")
		ptype, g = parts[0], parts[1]
	}

	logger.Debugf("Parsed package name: Type: %s Group: %s Name: %s", ptype, g, n)
	if !ok {
		logger.Debugf("Could not parse package name: %s", pkg.PackageName)
		return nil, fmt.Errorf("could not parse package name %s", pkg.PackageName)
	}

	ecosysystem, err := sbom_utils.PurlTypeToLockfileEcosystem(ptype)
	if err != nil {
		logger.Debugf("Unknown Supported Ecosystem type %s", ptype)
		return nil, err
	}

	version, _, _ := attemptParsePackageVersionExpression(pkg.PackageVersion)
	pd := &packagefile.PackageDetails{
		Name:      n,
		Group:     g,
		Version:   version,
		Ecosystem: ecosysystem,
		CompareAs: ecosysystem,
		SpdxRef:   pkg,
	}
	return pd, nil
}

// attempParsePackageName extracts package type, group, and name from the input string.
// The input string should have the format: "<package_type>:<group>/<name>"
// If the input doesn't match the expected format, the function returns false.
// Return type, group, name, bool
func attempParsePackageName(input string) (string, string, string, bool) {
	// Define a regular expression pattern to match the expected format.
	// Pattern breakdown: (.*?):(.*?)/(.*?)
	// 1. (.*?):   Match and capture the package type
	// 2. (.*?)/   Match and capture the group (optional)
	// 3. (.*?)    Match and capture the name
	pattern := regexp.MustCompile(`^((.+):)?((.+)/)?(.*)$`)
	matches := pattern.FindStringSubmatch(input)

	if len(matches) != 6 {
		return "", "", "", false
	}

	version := matches[5]
	if version == "" {
		version = "0.0.0"
	}

	return matches[2], matches[4], version, true
}

/*
Attempt parsing version information from the version expression.
*/
func attemptParsePackageVersionExpression(versionExpr string) (version, op string, ok bool) {
	pattern := regexp.MustCompile(`^\s*([<>=!~]+)?\s*([0-9]+\.[0-9]+(\.[0-9]+)?)?\s*$`)
	matches := pattern.FindStringSubmatch(versionExpr)

	if len(matches) != 4 {
		return "0.0.0", "", false
	}

	op = strings.TrimSpace(matches[1])
	version = strings.TrimSpace(matches[2])

	return version, op, true
}

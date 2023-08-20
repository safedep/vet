package spdx_sbom

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/parser/custom/spdx_sbom/packagefile"
	"github.com/spdx/tools-golang/spdx"
	packageurl "github.com/package-url/packageurl-go"
	spdx_json "github.com/spdx/tools-golang/json"
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
	// open the SPDX file
	r, err := os.Open(pathToLockfile)
	if err != nil {
		logger.Debugf("Error while opening %v for reading: %v", pathToLockfile, err)
		return nil, err
	}
	defer r.Close()

	// try to load the SPDX file's contents as a json file
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

func ParsePurlType(purl_type string) (lockfile.Ecosystem, bool) {
	KnownTypes := map[string]lockfile.Ecosystem{
		packageurl.TypeCargo:    lockfile.CargoEcosystem,
		packageurl.TypeComposer: lockfile.ComposerEcosystem,
		packageurl.TypeGolang:   lockfile.GoEcosystem,
		packageurl.TypeMaven:    lockfile.MavenEcosystem,
		packageurl.TypeNPM:      lockfile.NpmEcosystem,
		packageurl.TypeNuget:    lockfile.NuGetEcosystem,
		packageurl.TypePyPi: lockfile.PipEcosystem,
		"pip":               lockfile.PipEcosystem,
	}
	eco, ok := KnownTypes[purl_type]
	return eco, ok
}

func parsePackage(pkg *spdx.Package) (*packagefile.PackageDetails, error) {

	// Attempt parsing from purl
	pd, err := parsePackageFromPurl(pkg)
	if pd != nil {
		return pd, nil
	}

	// Attempt parsing from package detials
	pd, err = parsePackageFromPackageDetails(pkg)
	return pd, err
}

// Parse from Purl if available. It is a reliable parsing technique
func parsePackageFromPurl(pkg *spdx.Package) (*packagefile.PackageDetails, error) {

	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == "purl" {
			instance, err := packageurl.FromString(ref.Locator)
			if err != nil {
				return nil, err
			}
			name := instance.Name
			if instance.Namespace != "" {
				name = fmt.Sprintf("%s:%s", instance.Namespace, instance.Name)
			}
			ecosysystem, ok := ParsePurlType(instance.Type)
			if !ok {
				logger.Debugf("Unknown Supported Ecosystem type %s", instance.Type)
				return nil, fmt.Errorf("Unknown Supported Ecosystem type %s", instance.Type)
			}
			pd := &packagefile.PackageDetails{
				Name:      name,
				Version:   instance.Version,
				Ecosystem: ecosysystem,
				CompareAs: ecosysystem,
				SpdxRef:   pkg,
			}
			return pd, nil
		}
	}
	//When nothing found
	return nil, nil
}

// Parse from packahge details, if available. It is bit Unreliable Parsing
func parsePackageFromPackageDetails(pkg *spdx.Package) (*packagefile.PackageDetails, error) {
	ptype, g, n, ok := attempParsePackageName(pkg.PackageName)
	logger.Debugf("Parsed Package Name: type: %s Group: %s Name: %s", ptype, g, n)
	if !ok {
		logger.Debugf("Could not parse package name  %s", pkg.PackageName)
		return nil, fmt.Errorf("Could not parse package name %s", pkg.PackageName)
	}

	ecosysystem, ok := ParsePurlType(ptype)
	if !ok {
		logger.Debugf("Unknown Supported Ecosystem type %s", ptype)
		return nil, fmt.Errorf("Unknown Supported Ecosystem type %s", ptype)
	}

	name := n
	if g != "" {
		name = fmt.Sprintf("%s:%s", g, n)
	}

	version, _, _ := attemptParsePackageVersionExpression(pkg.PackageVersion)
	pd := &packagefile.PackageDetails{
		Name:      name,
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
	version := matches[5]

	if matches[5] == "" {
		version = "0.0.0"
	}

	if len(matches) != 6 {
		return "", "", "", false
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

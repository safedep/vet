package parser

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/common/utils/version"
	"github.com/safedep/vet/pkg/models"
)

// The GitHub Dependency Graph API writes a package name as "<type>:<group>/<name>"
// with the group optional. Example: "pip:flake8", "actions:actions/checkout"
var spdxPackageNamePattern = regexp.MustCompile(`^((.+):)?((.+)/)?(.*)$`)

func parseSbomSpdxAsGraph(path string, config *ParserConfig) (*models.PackageManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = file.Close() }()

	doc, err := spdxjson.Read(file)
	if err != nil {
		return nil, err
	}

	// The described elements are the subjects of the document, not dependencies of
	// it. They anchor the graph like the CycloneDX metadata component.
	describedRefs := spdxDescribedElements(doc)

	// A package carrying no element ID cannot be addressed by a relationship, so
	// it stays out of this map while still joining the manifest.
	refMap := make(map[spdx.ElementID]*models.Package)

	manifest := models.NewPackageManifestFromLocal(path, models.EcosystemSpdxSBOM)
	for _, spdxPackage := range doc.Packages {
		ref := spdxPackage.PackageSPDXIdentifier
		if _, described := describedRefs[ref]; described {
			continue
		}

		pkg, err := spdxExtractPackage(spdxPackage)
		if err != nil {
			// A document holds packages from ecosystems we do not support.
			// Losing one of them must not lose the document.
			logger.Debugf("Failed to extract SPDX package %s: %v",
				spdxPackage.PackageName, err)
			continue
		}

		if ref != "" {
			refMap[ref] = pkg
		}

		manifest.AddPackage(pkg)
	}

	graphPresent := false
	for _, relationship := range doc.Relationships {
		dependent, dependency, ok := spdxDependencyEdge(relationship)
		if !ok {
			continue
		}

		dependsOnPkg, ok := refMap[dependency]
		if !ok {
			logger.Debugf("%s depends on %s which is not found in refMap",
				dependent, dependency)
			continue
		}

		// A dependency of a described element is a root of the graph
		if _, described := describedRefs[dependent]; described {
			manifest.DependencyGraph.AddRootNode(dependsOnPkg)
			graphPresent = true

			continue
		}

		pkg, ok := refMap[dependent]
		if !ok {
			logger.Debugf("Dependency ref: %s not found in refMap", dependent)
			continue
		}

		manifest.DependencyGraph.AddDependency(pkg, dependsOnPkg)
		graphPresent = true
	}

	logger.Infof("Resolved %d packages as graph from SPDX document: %s",
		len(manifest.GetPackages()), path)

	// SPDX does not require a document to relate its packages, so an empty graph
	// would be a lie
	manifest.DependencyGraph.SetPresent(graphPresent)

	return manifest, nil
}

// The JSON reader builds a DESCRIBES relationship out of the documentDescribes
// field for SPDX 2.2 and 2.3, so reading the relationships covers both spellings.
func spdxDescribedElements(doc *spdx.Document) map[spdx.ElementID]struct{} {
	described := make(map[spdx.ElementID]struct{})

	for _, relationship := range doc.Relationships {
		var ref spdx.DocElementID

		switch relationship.Relationship {
		case spdxcommon.TypeRelationshipDescribe:
			ref = relationship.RefB
		case spdxcommon.TypeRelationshipDescribeBy:
			ref = relationship.RefA
		default:
			continue
		}

		if spdxAddressesLocalElement(ref) {
			described[ref.ElementRefID] = struct{}{}
		}
	}

	return described
}

// DEPENDENCY_OF is DEPENDS_ON with its operands swapped
func spdxDependencyEdge(relationship *spdx.Relationship) (spdx.ElementID, spdx.ElementID, bool) {
	var dependent, dependency spdx.DocElementID

	switch relationship.Relationship {
	case spdxcommon.TypeRelationshipDependsOn:
		dependent, dependency = relationship.RefA, relationship.RefB
	case spdxcommon.TypeRelationshipDependencyOf:
		dependent, dependency = relationship.RefB, relationship.RefA
	default:
		return "", "", false
	}

	if !spdxAddressesLocalElement(dependent) || !spdxAddressesLocalElement(dependency) {
		return "", "", false
	}

	return dependent.ElementRefID, dependency.ElementRefID, true
}

// A reference that names another document, or that carries no element at all
// such as NONE and NOASSERTION, addresses no package in this manifest.
func spdxAddressesLocalElement(ref spdx.DocElementID) bool {
	return ref.DocumentRefID == "" && ref.ElementRefID != ""
}

// A PURL resolves a package reliably. Roughly half the packages in a GitHub
// Dependency Graph export carry none, so the package name is the fallback.
func spdxExtractPackage(spdxPackage *spdx.Package) (*models.Package, error) {
	for _, ref := range spdxPackage.PackageExternalReferences {
		if ref == nil || ref.RefType != "purl" {
			continue
		}

		parsedPurl, err := purl.ParsePackageUrl(ref.Locator)
		if err != nil {
			// A PURL we cannot read must not cost us a package the name identifies
			logger.Debugf("Failed to parse purl %s: %v", ref.Locator, err)
			continue
		}

		return &models.Package{
			PackageDetails: parsedPurl.GetPackageDetails(),
		}, nil
	}

	return spdxExtractPackageFromName(spdxPackage)
}

func spdxExtractPackageFromName(spdxPackage *spdx.Package) (*models.Package, error) {
	packageType, group, name, ok := spdxParsePackageName(spdxPackage.PackageName)
	if !ok {
		return nil, fmt.Errorf("could not parse package name %s", spdxPackage.PackageName)
	}

	synthesized := packageurl.NewPackageURL(packageType, group, name,
		version.BestEffort(spdxPackage.PackageVersion), nil, "")

	parsedPurl, err := purl.ParsePackageUrl(synthesized.ToString())
	if err != nil {
		return nil, err
	}

	return &models.Package{
		PackageDetails: parsedPurl.GetPackageDetails(),
	}, nil
}

func spdxParsePackageName(input string) (packageType, group, name string, ok bool) {
	matches := spdxPackageNamePattern.FindStringSubmatch(input)
	if len(matches) != 6 {
		return "", "", "", false
	}

	packageType, group, name = matches[2], matches[4], matches[5]

	// The type capture is greedy, so a group written with a colon lands in it:
	// "maven:org.acme:lib" leaves the type holding "maven:org.acme"
	if t, g, found := strings.Cut(packageType, ":"); found {
		packageType, group = t, g
	}

	if name == "" {
		return "", "", "", false
	}

	return packageType, group, name, true
}

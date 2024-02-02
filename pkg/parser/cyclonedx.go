package parser

import (
	"bufio"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"
)

func parseSbomCycloneDxAsGraph(path string, config *ParserConfig) (*models.PackageManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	bom := cdx.NewBOM()
	bomReader := bufio.NewReader(file)

	format := cdx.BOMFileFormatJSON
	if len(path) > 4 && path[len(path)-4:] == ".xml" {
		format = cdx.BOMFileFormatXML
	}

	decoder := cdx.NewBOMDecoder(bomReader, format)
	if err = decoder.Decode(bom); err != nil {
		return nil, err
	}

	// Fail fast if the BOM does not have the main (app) component
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil, fmt.Errorf("Invalid CycloneDX SBOM: Metadata or Component is nil")
	}

	// Maintain a cache of BOM / packageUrl ref to package mapping for re-use while adding
	// dependency relations
	bomRefMap := make(map[string]*models.Package)

	// Lets start by adding the main component
	ref, pkg, err := cdxExtractPackageFromComponent(*bom.Metadata.Component)
	if err != nil {
		return nil, fmt.Errorf("failed to extract main package from component: %v", err)
	}

	bomRefMap[ref] = pkg

	manifest := models.NewPackageManifest(path, models.EcosystemCyDxSBOM)
	components := utils.SafelyGetValue(bom.Components)

	// Iterate over all components in the BOM and add the package in dependency graph
	// This just adds the nodes in the graph without any relations
	for _, component := range components {
		ref, pkg, err := cdxExtractPackageFromComponent(component)
		if err != nil {
			logger.Errorf("Failed to extract package from component %v: %v",
				component, err)
			continue
		}

		bomRefMap[ref] = pkg
		manifest.AddPackage(pkg)
	}

	// Iterate over the dependency relations and add the edges in the graph
	depedencyRelations := utils.SafelyGetValue(bom.Dependencies)
	for _, dependencyRelation := range depedencyRelations {
		// We must have seen the package while enumerating components without which
		// we cannot add a dependency relation
		pkg, ok := bomRefMap[dependencyRelation.Ref]
		if !ok {
			logger.Errorf("Dependency ref: %s not found in bomRefMap", dependencyRelation.Ref)
			continue
		}

		// We lookup the package in the bomRefMap and add the dependency relation
		// We fail if we cannot find the package because as per CycloneDX spec it seems
		// every known component must be defined.
		dependencies := utils.SafelyGetValue(dependencyRelation.Dependencies)
		for _, dependency := range dependencies {
			dependsOnPkg, ok := bomRefMap[dependency]
			if !ok {
				logger.Errorf("%s depends on %s which is not found in bomRefMap",
					dependencyRelation.Ref, dependency)
				continue
			}

			if cdxIsMainComponent(bom, dependencyRelation.Ref) {
				manifest.DependencyGraph.AddRootNode(dependsOnPkg)
			} else {
				manifest.DependencyGraph.AddDependency(pkg, dependsOnPkg)
			}
		}
	}

	logger.Infof("Resolved %d packages as graph from BOM: %s",
		len(manifest.GetPackages()), path)

	// We consider that a dependency graph is constructed from BOM
	// only when we find at least 1 dependency relation.
	if len(depedencyRelations) > 0 {
		manifest.DependencyGraph.SetPresent(true)
	}

	return manifest, nil
}

func cdxIsMainComponent(bom *cdx.BOM, ref string) bool {
	return bom.Metadata != nil && bom.Metadata.Component != nil &&
		(bom.Metadata.Component.PackageURL == ref || bom.Metadata.Component.BOMRef == ref)
}

func cdxExtractPackageFromComponent(component cdx.Component) (string, *models.Package, error) {
	pUrl := component.PackageURL
	if pUrl == "" {
		pUrl = component.BOMRef
	}

	if pUrl == "" {
		return "", nil, fmt.Errorf("Invalid CycloneDX SBOM: PackageURL or BOMRef is nil")
	}

	parsedPurl, err := purl.ParsePackageUrl(pUrl)
	if err != nil {
		return "", nil, err
	}

	return pUrl, &models.Package{
		PackageDetails: parsedPurl.GetPackageDetails(),
	}, nil
}

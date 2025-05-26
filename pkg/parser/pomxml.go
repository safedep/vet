package parser

import (
	"context"
	"fmt"
	scalibr "github.com/google/osv-scalibr"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/plugin"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

// parseMavenPomXmlFile parses the pom.xml file in a maven project.
// Its finds the dependency from Maven Registry, and also from Parent Maven BOM
// We use osc-scalibr's java/pomxmlnet (with Net, or Network) to fetch dependency from registry.
func parseMavenPomXmlFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	// Java/PomXMLNet extractor
	ext, err := el.ExtractorsFromNames([]string{"java/pomxmlnet"})
	if err != nil {
		logger.Errorf("Failed to create java/pomxmlnet extractor form osv-scalibr: %s", err.Error())
		return nil, fmt.Errorf("failed to create java/pomxmlnet extractor: %w", err)
	}

	// Capability is required for filtering the extractors,
	// For example, osv-scalibr has 33 default extractors for instance, go, JavaScript, java/gradel, java/pomxml etc.
	// Then this capability is used to filter with some property, like network (as required by our java/pomxmlnet)
	capability := &plugin.Capabilities{
		OS:            plugin.OSAny,
		Network:       plugin.NetworkOnline, // Network Online is Crucial for java/pomxml
		DirectFS:      true,
		RunningSystem: true,
	}

	// Apply capabilities
	ext = el.FilterByCapabilities(ext, capability)

	// Find the default scan root.
	scanRoots, err := scalibrDefaultScanRoots()
	if err != nil {
		logger.Errorf("Failed to create scan roots for osv-scalibr: %s", err.Error())
		return nil, fmt.Errorf("failed to create scan roots for osv-scalibr: %w", err)
	}

	// ScanConfig
	config := &scalibr.ScanConfig{
		ScanRoots:            scanRoots,
		FilesystemExtractors: ext,
		Capabilities:         capability,
		PathsToExtract:       []string{lockfilePath},
	}

	result := scalibr.New().Scan(context.Background(), config)

	if result.Status.Status != plugin.ScanStatusSucceeded {
		logger.Warnf("osv-scalibr scan did not performed scan with success")
		return nil, fmt.Errorf("osv-scalibr scan did not performed scan with success: Status %s", result.Status.String())
	}

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemMaven)

	for _, pkg := range result.Inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemMaven, pkg.Name, pkg.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}

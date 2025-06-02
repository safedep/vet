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

// parseGoModFile parses the go.mod file of the  project.
// We use osc-scalibr's go/gomod to fetch dependency.
func parseGoModFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	// go/gomod extractor
	ext, err := el.ExtractorsFromNames([]string{"go/gomod"})
	if err != nil {
		logger.Errorf("Failed to create go/gomod extractor form osv-scalibr: %s", err.Error())
		return nil, fmt.Errorf("failed to create go/gomod extractor: %w", err)
	}

	// Capability is required for filtering the extractors,
	// For example, osv-scalibr has 33 default extractors for instance, go, JavaScript, java/gradel, java/pomxml etc.
	capability := &plugin.Capabilities{
		OS:            plugin.OSAny,
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

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemGo)

	for _, pkg := range result.Inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemGo, pkg.Name, pkg.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}

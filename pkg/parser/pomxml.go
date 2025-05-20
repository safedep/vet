package parser

import (
	"context"
	"fmt"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/binary/platform"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"os"
)

// parseMavenPomXmlFile parses the pom.xml file in a maven project.
// Its finds the dependency from Maven Registry, and also from Parent Maven BOM
// We use osc-scalibr's java/pomxmlnet (with Net, or Network) to fetch dependency from registry.
func parseMavenPomXmlFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	// Java/PomXMLNet extractor
	ext, err := el.ExtractorsFromNames([]string{"java/pomxmlnet"})
	if err != nil {
		logger.Errorf("Failed to create java/pomxmlnet extractor form osv-scalibr: %v", err)
		return nil, fmt.Errorf("failed to create java/pomxmlnet extractor: %v", err.Error())
	}

	// Capability is required for filtering the extractors,
	// For example, osv-scalibr has 33 default extractors for instance, go, JavaScript, java/gradel, java/pomxml etc.
	// Then this capability is used to filter with some property, like network (as required by our java/pomxmlnet)
	// Capability is required, even if its empty.
	capability := &plugin.Capabilities{
		OS:            plugin.OSLinux,
		Network:       plugin.NetworkOnline,
		DirectFS:      true,
		RunningSystem: true,
	}

	// Apply capabilities
	ext = el.FilterByCapabilities(ext, capability)

	// Find the default scan root.
	scanRoots, err := scanRoots()
	if err != nil {
		logger.Errorf("Failed to create scan roots for osv-scalibr: %v", err)
		return nil, fmt.Errorf("failed to create scan roots for osv-scalibr: %v", err.Error())
	}

	// ScanConfig
	config := &scalibr.ScanConfig{
		ScanRoots:            scanRoots,
		FilesystemExtractors: ext,
		Capabilities:         capability,
		PathsToExtract:       []string{lockfilePath},
	}

	result := scalibr.New().Scan(context.Background(), config)

	fmt.Println(result.Status.String())

	for _, r := range result.Inventory.Packages {
		fmt.Println(r.Name, r.Version)
	}

	os.Exit(1)
	return nil, nil
}

// scanRoots function returns the default scan root required for osv-scalibr
// Default is `/`
func scanRoots() ([]*scalibrfs.ScanRoot, error) {
	var scanRoots []*scalibrfs.ScanRoot
	var scanRootPaths []string
	var err error
	if scanRootPaths, err = platform.DefaultScanRoots(false); err != nil {
		return nil, err
	}
	for _, r := range scanRootPaths {
		scanRoots = append(scanRoots, &scalibrfs.ScanRoot{FS: scalibrfs.DirFS(r), Path: r})
	}
	return scanRoots, nil
}

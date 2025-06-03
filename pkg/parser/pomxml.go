package parser

import (
	"context"
	"fmt"
	scalibr "github.com/google/osv-scalibr"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/plugin"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"io"
	"os"
	"path"
	"path/filepath"
)

// parseMavenPomXmlFile parses the pom.xml file in a maven project.
// Its finds the dependency from Maven Registry, and also from Parent Maven BOM
// We use osc-scalibr's java/pomxmlnet (with Net, or Network) to fetch dependency from registry.
func parseMavenPomXmlFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	if filepath.Base(lockfilePath) != "pom.xml" {
		// create a temp directory and put this file with the name pom.xml
		newPath, err := copyLockfileToTempDir(lockfilePath, "pom.xml")
		if err != nil {
			return nil, fmt.Errorf("could not copy lockfile to temp directory: %w", err)
		}
		lockfilePath = newPath
	}

	// Java/PomXMLNet extractor
	// need filename to be pom.xml
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

func copyLockfileToTempDir(sourceFileName, destFileName string) (string, error) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "vet-scan-*")
	if err != nil {
		return "", err
	}
	// TODO: remove this dir

	filePath := path.Join(tempDir, destFileName)
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	sourceData, err := os.Open(sourceFileName)
	if err != nil {
		return "", err
	}
	defer sourceData.Close()

	_, err = io.Copy(file, sourceData)
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

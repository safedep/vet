package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
)

func parseCyclonedxSBOM(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	details := []lockfile.PackageDetails{}

	bom := cdx.NewBOM()
	logger.Infof("Starting SBOM decoding...")
	if file, err := os.Open(pathToLockfile); err != nil {
		logger.Debugf("Error in Decoding the SBOM file %v", err)
		return nil, err
	} else {
		defer file.Close()
		sbom_content := bufio.NewReader(file)
		decoder := cdx.NewBOMDecoder(sbom_content, cdx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			logger.Debugf("Error in Decoding the SBOM file %v", err)
			return nil, err
		}
	}

	// Components is a pointer array and it can be empty
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			if d, err := convertSbomComponent2LPD(&comp); err != nil {
				logger.Debugf("Failed converting sbom to lockfile component: %v", err)
			} else {
				details = append(details, *d)
			}
		}
	}

	logger.Debugf("Found number of packages %d\n", len(details))

	return details, nil
}

func convertSbomComponent2LPD(comp *cdx.Component) (*lockfile.PackageDetails, error) {
	var name string
	if comp.Group != "" {
		name = fmt.Sprintf("%s:%s", comp.Group, comp.Name)
	} else {
		name = comp.Name
	}
	var ecosysystem lockfile.Ecosystem
	if eco, err := convertBomRefAsEcosystem(comp.BOMRef); err != nil {
		return nil, err
	} else {
		ecosysystem = eco
	}

	d := lockfile.PackageDetails{
		Name:      name,
		Version:   comp.Version,
		Ecosystem: ecosysystem,
		CompareAs: ecosysystem,
	}

	return &d, nil
}

func convertBomRefAsEcosystem(bomref string) (lockfile.Ecosystem, error) {
	if strings.Contains(bomref, "pkg:pypi") {
		return lockfile.PipEcosystem, nil
	} else if strings.Contains(bomref, "pkg:npm") {
		return lockfile.NpmEcosystem, nil
	} else {
		// Return an error, the ecosystem here does not matter
		return lockfile.NpmEcosystem, fmt.Errorf("failed parsing bomref %s to ecosystem", bomref)
	}
}

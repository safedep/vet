package parser

import (
	"fmt"
	// "errors"
	"os"
	"strings"
	"bufio"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// https://packaging.python.org/en/latest/specifications/binary-distribution-format/
func parseCyclonedxSBOM(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	details := []lockfile.PackageDetails{}

	bom := new(cdx.BOM)
	if file, err := os.Open(pathToLockfile); err != nil {
		logger.Warnf("Error opening sbom file %v", err)
		return nil, err
	} else {
		sbom_content := bufio.NewReader(file)
		decoder := cdx.NewBOMDecoder(sbom_content, cdx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	}
	
	// fmt.Printf("%v", bom.Components)
	for _, comp := range *bom.Components {
		if d, err := convertSbomComponent2LPD(&comp); err != nil {
			// fmt.Println(err)
			logger.Warnf("Failed Converting sbom to lockfile component.  %v", err)
		} else {
			// fmt.Println(*d)
			details = append(details, *d)
		}
	}

	// fmt.Printf("%v", details)
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
		return lockfile.NpmEcosystem, fmt.Errorf("Failed parsing %s to ecosystem", bomref)
	}
}

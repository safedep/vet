package parser

import (
	"fmt"
	// "errors"
	"os"
	"encoding/json"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
)

// Define the struct types that match the JSON structure
type Bom struct {
	BomFormat   string       `json:"bomFormat"`
	SpecVersion string       `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version     int          `json:"version"`
	Metadata    Metadata     `json:"metadata"`
	Components  []Component  `json:"components"`
	Services    []interface{} `json:"services"`  // Assuming services is an array, but it's empty in the provided sample
	// You can add more fields if needed...
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      []Tool     `json:"tools"`
	Authors    []Author   `json:"authors"`
	Component  Component  `json:"component"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Component struct {
	Publisher   string `json:"publisher"`
	Group       string `json:"group"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Purl        string `json:"purl"`
	Type        string `json:"type"`
	BomRef      string `json:"bom-ref"`
	// Add more fields if needed, for example, licenses
}

// https://packaging.python.org/en/latest/specifications/binary-distribution-format/
func parseCyclonedxSBOM(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	details := []lockfile.PackageDetails{}

	var bom Bom
	if vet_output_file_content, err := os.ReadFile(pathToLockfile); err != nil {
		logger.Warnf("Error reading sbom file %v", err)
		return nil, err
	} else {
		// Unmarshal the JSON string into the Bom struct
		if err := json.Unmarshal([]byte(vet_output_file_content), &bom); err != nil {
			logger.Warnf("Error parsing JSON: %v", err)
			return nil, err
		}
	}
	
	fmt.Printf("%v", bom.Components)
	for _, comp := range bom.Components {
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

func convertSbomComponent2LPD(comp *Component) (*lockfile.PackageDetails, error) {
	var name string
	if comp.Group != "" {
		name = fmt.Sprintf("%s:%s", comp.Group, comp.Name)
	} else {
		name = comp.Name
	}
	var ecosysystem lockfile.Ecosystem
	if eco, err := convertBomRefAsEcosystem(comp.BomRef); err != nil {
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

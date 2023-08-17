package py

import (
	"strings" 
	"regexp"
	// "github.com/safedep/vet/pkg/common/logger"
	"github.com/google/osv-scanner/pkg/lockfile"
)


func ParseSetuppy(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	details := []lockfile.PackageDetails{}

	// Get and print dependency strings from the setup.py file
	if stringConstants, err := GetDependencies(pathToLockfile); err != nil {
		return details, err
	} else {
		for _, constant := range stringConstants {
			if pd, err := parsePythonPackageSpec(constant); err != nil{
				return details, err
			} else {
				details = append(details, pd)
			}
		}
	}
	return details, nil
}

// Return Dependency Strings
func GetDependencies(pathToLockfile string) ([]string, error) {
	setuppy_parser := NewSetuppyParserViaSyntaxTree()
	// Get and print dependency strings from the setup.py file
	if stringConstants, err := setuppy_parser.GetDependencyStrings(pathToLockfile); err != nil {
		return nil, err
	} else {
		return stringConstants, nil
	}
}



// The order of regexp is important as it gives the precedence of range that we
// want to consider. Exact match is always highest precendence. We pessimistically
// consider the lower version in the range
var pyWheelVersionMatchers []*regexp.Regexp = []*regexp.Regexp{
	regexp.MustCompile("==([0-9\\.]+)"),
	regexp.MustCompile(">([0-9\\.]+)"),
	regexp.MustCompile(">=([0-9\\.]+)"),
	regexp.MustCompile("<([0-9\\.]+)"),
	regexp.MustCompile("<=([0-9\\.]+)"),
	regexp.MustCompile("~=([0-9\\.]+)"),
}


// https://peps.python.org/pep-0440/
// https://peps.python.org/pep-0508/
// Parsing python dist version spec is not easy. We need to use the spec grammar
// to do it correctly. Taking shortcut here by only using the name as the first
// iteration ignoring the version
func parsePythonPackageSpec(pkgSpec string) (lockfile.PackageDetails, error) {
	parts := strings.SplitN(pkgSpec, " ", 2)
	name := parts[0]
	version := "0.0.0"

	rest := ""
	if len(parts) > 1 {
		rest = parts[1]
	}

	// Try to match version by regex
	for _, r := range pyWheelVersionMatchers {
		res := r.FindAllStringSubmatch(rest, 1)
		if (len(res) == 0) || (len(res[0]) < 2) {
			continue
		}

		version = res[0][1]
		break
	}

	return lockfile.PackageDetails{
		Name:      name,
		Version:   version,
		Ecosystem: lockfile.PipEcosystem,
		CompareAs: lockfile.PipEcosystem,
	}, nil
}

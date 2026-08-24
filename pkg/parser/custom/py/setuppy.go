package py

import (
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"

	"github.com/safedep/vet/pkg/common/logger"
	regex_utils "github.com/safedep/vet/pkg/common/utils/regex"
	"github.com/safedep/vet/pkg/common/utils/version"
)

func ParseSetuppy(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	details := []lockfile.PackageDetails{}

	// Get and print dependency strings from the setup.py file
	if stringConstants, err := getDependencies(pathToLockfile); err != nil {
		return details, err
	} else {
		for _, constant := range stringConstants {
			pd := parseRequirementsFileLine(constant)
			details = append(details, pd)
		}
	}

	logger.Debugf("Parsed Packaged Details %v", details)
	return details, nil
}

// Return Dependency Strings in raw format such as "xxx>=123"
func getDependencies(pathToLockfile string) ([]string, error) {
	setuppy_parser := newSetuppyParserViaSyntaxTree()
	// Get and print dependency strings from the setup.py file
	if stringConstants, err := setuppy_parser.getDependencyStrings(pathToLockfile); err != nil {
		return nil, err
	} else {
		return stringConstants, nil
	}
}

// todo: expand this to support more things, e.g.
//
//	https://pip.pypa.io/en/stable/reference/requirements-file-format/#example
func parseRequirementsFileLine(line string) lockfile.PackageDetails {
	// PEP 508 puts an environment marker after ";". It says when the
	// requirement applies, not which release, so it must not reach the version.
	requirement, _, _ := strings.Cut(line, ";")
	name, expr := cutRequirementOperator(requirement)

	return lockfile.PackageDetails{
		Name:      normalizedRequirementName(name),
		Version:   version.Resolve(expr),
		Ecosystem: lockfile.PipEcosystem,
		CompareAs: lockfile.PipEcosystem,
	}
}

func cutRequirementOperator(requirement string) (name, expr string) {
	at := strings.IndexAny(requirement, "<>=!~")
	if at < 0 {
		return strings.TrimSpace(requirement), ""
	}

	return strings.TrimSpace(requirement[:at]), requirement[at:]
}

// normalizedName ensures that the package name is normalized per PEP-0503
// and then removing "added support" syntax if present.
//
// This is done to ensure we don't miss any advisories, as while the OSV
// specification says that the normalized name should be used for advisories,
// that's not the case currently in our databases, _and_ Pip itself supports
// non-normalized names in the requirements.txt, so we need to normalize
// on both sides to ensure we don't have false negatives.
//
// It's possible that this will cause some false positives, but that is better
// than false negatives, and can be dealt with when/if it actually happens.
func normalizedRequirementName(name string) string {
	// per https://www.python.org/dev/peps/pep-0503/#normalized-names
	name = regex_utils.MustCompileAndCache(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, "[")

	return name
}

package parser

import (
	"archive/zip"
	"errors"
	"io"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
)

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

// https://packaging.python.org/en/latest/specifications/binary-distribution-format/
func parsePythonWheelDist(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	details := []lockfile.PackageDetails{}

	r, err := zip.OpenReader(pathToLockfile)
	if err != nil {
		return details, err
	}

	defer r.Close()
	for _, file := range r.File {
		if strings.HasSuffix(file.Name, ".dist-info/METADATA") {
			fd, err := file.Open()
			if err != nil {
				return details, err
			}

			defer fd.Close()
			return parsePythonPkgInfo(fd)
		}
	}

	return details, errors.New("no METADATA found inside wheel")
}

// https://packaging.python.org/en/latest/specifications/core-metadata/
func parsePythonPkgInfo(reader io.Reader) ([]lockfile.PackageDetails, error) {
	m, err := mail.ReadMessage(reader)
	if err != nil {
		return []lockfile.PackageDetails{}, err
	}

	// https://packaging.python.org/en/latest/specifications/core-metadata/#requires-dist-multiple-use
	if dists, ok := m.Header["Requires-Dist"]; ok {
		details := []lockfile.PackageDetails{}
		for _, dist := range dists {
			p, err := parsePythonPackageSpec(dist)
			if err != nil {
				logger.Errorf("Failed to parse python pkg spec: %s err: %v",
					dist, err)
				continue
			}

			details = append(details, p)
		}

		return details, nil
	}

	return []lockfile.PackageDetails{}, nil
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

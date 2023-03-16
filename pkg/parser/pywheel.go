package parser

import (
	"archive/zip"
	"errors"
	"io"
	"net/mail"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/logger"
)

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
	name := strings.SplitN(pkgSpec, " ", 2)[0]
	return lockfile.PackageDetails{
		Name:      name,
		Version:   "0.0.0",
		Ecosystem: lockfile.PipEcosystem,
		CompareAs: lockfile.PipEcosystem,
	}, nil
}

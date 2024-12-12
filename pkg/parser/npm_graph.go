package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
)

type npmPackageLockPackage struct {
	Version         string            `json:"version"`
	License         string            `json:"license"`
	Resolved        string            `json:"resolved"`
	Integrity       string            `json:"integrity"`
	Link            bool              `json:"link"`
	Dev             bool              `json:"dev"`
	Optional        bool              `json:"optional"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
type npmPackageLock struct {
	Name            string                           `json:"name"`
	Version         string                           `json:"version"`
	LockfileVersion int                              `json:"lockfileVersion"`
	Packages        map[string]npmPackageLockPackage `json:"packages"`
}

// https://docs.npmjs.com/cli/v10/configuring-npm/package-json
type npmPackageJson struct {
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Version         string            `json:"version"`
	Author          string            `json:"author"`
	Contributors    []string          `json:"contributors"`
	License         string            `json:"license"`
	Repository      string            `json:"repository"`
	Homepage        string            `json:"homepage"`
	Keywords        []string          `json:"keywords"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Engines         map[string]string `json:"engines"`
	Files           []string          `json:"files"`
	Scripts         map[string]string `json:"scripts"`
}

var (
	exactVersionMatchRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	startsWithDigitRegex   = regexp.MustCompile(`^[0-9]`)
	semverExtractorRegex   = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)
)

// Parse package.json. This is required because npm library packages do
// not lock dependencies (rightly so).
func parseNpmPackageJsonAsGraph(packageJsonPath string, config *ParserConfig) (*models.PackageManifest, error) {
	data, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return nil, err
	}

	var packageJson npmPackageJson
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&packageJson)
	if err != nil {
		return nil, err
	}

	logger.Debugf("npmGraphParser: Found %d dependencies in package.json",
		len(packageJson.Dependencies))

	manifest := models.NewPackageManifestFromLocal(packageJsonPath, models.EcosystemNpm)

	dependencies := packageJson.Dependencies
	if dependencies == nil {
		dependencies = make(map[string]string)
	}

	if config.IncludeDevDependencies {
		for k, v := range packageJson.DevDependencies {
			if _, ok := dependencies[k]; !ok {
				dependencies[k] = v
			} else {
				logger.Warnf("npmGraphParser: Dev dependency %s is already present in dependencies", k)
			}
		}
	}

	for depName, depVersion := range dependencies {
		// We are supporting only package dependencies. Actual dependencies
		// can be Url, Git URL, GitHub URL as well. We are not handling those
		// for now.

		resolvedVersion, err := npmVersionConstraintResolveVersion(depVersion)
		if err != nil {
			logger.Warnf("npmGraphParser: Could not resolve version for %s: %v", depVersion, err)
			continue
		}

		pkgDetails := models.NewPackageDetail(models.EcosystemNpm, depName, resolvedVersion)
		manifest.AddPackage(&models.Package{
			PackageDetails: pkgDetails,
		})
	}

	return manifest, nil
}

func parseNpmPackageLockAsGraph(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, err
	}

	var lockfile npmPackageLock
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&lockfile)
	if err != nil {
		return nil, err
	}

	if lockfile.LockfileVersion < 2 {
		return nil, fmt.Errorf("npmGraphParser: Unsupported lockfile version %d",
			lockfile.LockfileVersion)
	}

	logger.Debugf("npmGraphParser: Found %d packages in lockfile",
		len(lockfile.Packages))

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemNpm)
	dependencyGraph := manifest.DependencyGraph

	if dependencyGraph == nil {
		return nil, fmt.Errorf("npmGraphParser: Dependency graph is nil")
	}

	// Is this really optional or should we hard fail here?
	if app, ok := lockfile.Packages[""]; ok {
		defer func() {
			for depName, depVersion := range app.Dependencies {
				node := npmGraphFindBySemverRange(dependencyGraph, depName, depVersion)
				if node != nil {
					node.SetRoot(true)
				}
			}
		}()
	}

	// We will first add all the nodes in the graph then add the edges
	// The nature of package-lock.json is such that it can contain multiple
	// version of the same dependency. So while adding edges, we have to find the node
	// that fulfills the semver constraint of the dependent towards the dependency node.
	for pkgLocation, pkgInfo := range lockfile.Packages {
		// The application itself
		if pkgLocation == "" {
			continue
		}

		pkgName := utils.NpmNodeModulesPackagePathToName(pkgLocation)
		if pkgName == "" {
			logger.Debugf("npmGraphParser: Could not parse package name from location %s",
				pkgLocation)
			continue
		}

		if !config.IncludeDevDependencies && (pkgInfo.Dev || pkgInfo.Optional) {
			logger.Debugf("npmGraphParser: Skipping dev/optional package %s", pkgName)
			continue
		}

		pkgDetails := models.NewPackageDetail(models.EcosystemNpm, pkgName, pkgInfo.Version)
		pkg := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}

		// Add node
		dependencyGraph.AddNode(pkg)

		// Add edges (dependencies)
		for depName, depSemverRange := range pkgInfo.Dependencies {
			defer npmGraphAddDependencyRelation(dependencyGraph, pkg, depName, depSemverRange)
		}
	}

	dependencyGraph.SetPresent(true)
	return manifest, nil
}

// npmGraphAddDependencyRelation enumerates all nodes in the graph to find a node that matches semver constraint
// If found, it adds an edge from the node to the dependency node
func npmGraphAddDependencyRelation(graph *models.DependencyGraph[*models.Package],
	from *models.Package, name, semver string) {
	nodeTarget := npmGraphFindBySemverRange(graph, name, semver)
	if nodeTarget == nil {
		logger.Debugf("npmGraphParser: Could not find a node that matches semver constraint %s for dependency %s",
			semver, name)
		return
	}

	logger.Debugf("npmGraphParser: Adding dependency for %s@%s to %s@%s",
		from.GetName(), from.GetVersion(),
		nodeTarget.Data.GetName(), nodeTarget.Data.GetVersion())

	graph.AddDependency(from, nodeTarget.Data)
}

func npmGraphFindBySemverRange(graph *models.DependencyGraph[*models.Package],
	name, semver string) *models.DependencyGraphNode[*models.Package] {
	return utils.FindDependencyGraphNodeBySemverRange(graph, name, semver)
}

// There is no way for us to resolve the version from a semver constraint
// because it depends on a lot of factors including other dependencies, platform,
// node version etc. To keep things simple, we will choose the lowest version
func npmVersionConstraintResolveVersion(constraint string) (string, error) {
	if exactVersionMatchRegex.MatchString(constraint) {
		return constraint, nil
	}

	if startsWithDigitRegex.MatchString(constraint) {
		return constraint, nil
	}

	if semverExtractorRegex.MatchString(constraint) {
		return semverExtractorRegex.FindString(constraint), nil
	}

	return constraint, nil
}

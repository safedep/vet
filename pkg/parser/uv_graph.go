package parser

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type uvLockPackage struct {
	Name                 string                    `toml:"name"`
	Version              string                    `toml:"version"`
	Source               uvLockPackageSource       `toml:"source"`
	Dependencies         []uvDependency            `toml:"dependencies"`
	OptionalDependencies map[string][]uvDependency `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDependency `toml:"dev-dependencies"`
	Metadata             Metadata                  `toml:"metadata"`
}

type uvLockPackageSource struct {
	Type     string `toml:"type"`
	URL      string `toml:"url"`
	Subdir   string `toml:"subdir,omitempty"`
	Ref      string `toml:"ref,omitempty"`
	Virtual  string `toml:"virtual,omitempty"`
	Editable string `toml:"editable,omitempty"`
}

type uvDependency struct {
	Name string `toml:"name"`
}

type uvLockFile struct {
	Version  int             `toml:"version"`
	Packages []uvLockPackage `toml:"package"`
}

type RequiresDist struct {
	Name      string   `toml:"name"`
	Extras    []string `toml:"extras,omitempty"`
	Specifier string   `toml:"specifier"`
}

type Metadata struct {
	RequiresDist []RequiresDist `toml:"requires-dist"`
}

func parseUvPackageLockAsGraph(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, err
	}

	var parsedLockFile *uvLockFile
	_, err = toml.NewDecoder(bytes.NewReader(data)).Decode(&parsedLockFile)
	if err != nil {
		return nil, err
	}

	logger.Debugf("uvGraphParser: Found %d packages in lockfile",
		len(parsedLockFile.Packages))

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemPyPI)
	dependencyGraph := manifest.DependencyGraph

	if dependencyGraph == nil {
		return nil, fmt.Errorf("uvGraphParser: Dependency graph is nil")
	}

	defer func() {
		for _, pkg := range parsedLockFile.Packages {
			if pkg.Source.Virtual != "" || pkg.Source.Editable != "" {
				for _, dep := range pkg.Dependencies {
					node := uvFindPackageByName(dependencyGraph, dep.Name)
					if node != nil {
						node.SetRoot(true)
					}
				}
			}
		}
	}()

	for _, pkgInfo := range parsedLockFile.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemPyPI, pkgInfo.Name, pkgInfo.Version)
		pkg := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}

		if pkgInfo.Source.Virtual == "" || pkgInfo.Source.Editable == "" {
			dependencyGraph.AddNode(pkg)
		}

		for _, depName := range pkgInfo.Dependencies {
			defer uvGraphAddDependencyRelation(dependencyGraph, pkg, depName.Name)
		}

		for _, deps := range pkgInfo.OptionalDependencies {
			if !config.IncludeDevDependencies {
				continue
			}

			for _, depName := range deps {
				defer uvGraphAddDependencyRelation(dependencyGraph, pkg, depName.Name)
			}
		}

		for _, deps := range pkgInfo.DevDependencies {
			if !config.IncludeDevDependencies {
				continue
			}

			for _, depName := range deps {
				defer uvGraphAddDependencyRelation(dependencyGraph, pkg, depName.Name)
			}
		}
	}
	dependencyGraph.SetPresent(true)
	return manifest, nil
}

func uvGraphAddDependencyRelation(graph *models.DependencyGraph[*models.Package], from *models.Package, name string) {
	targetPkg := uvFindPackageByName(graph, name)
	if targetPkg == nil {
		logger.Debugf("uvGraphParser: Missing dependency %s for %s",
			name, from.Name)
		return
	}

	graph.AddDependency(from, targetPkg.Data)
}

func uvFindPackageByName(graph *models.DependencyGraph[*models.Package], name string) *models.DependencyGraphNode[*models.Package] {
	for _, node := range graph.GetNodes() {
		if strings.EqualFold(node.Data.GetName(), name) {
			return node
		}
	}
	return nil
}

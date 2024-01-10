package utils

import (
	"strings"

	"github.com/safedep/dry/semver"
	"github.com/safedep/vet/pkg/models"
)

func FindDependencyGraphNodeBySemverRange(graph *models.DependencyGraph[*models.Package],
	name string, rangeStr string) *models.DependencyGraphNode[*models.Package] {
	for _, node := range graph.GetNodes() {
		if !strings.EqualFold(node.Data.GetName(), name) {
			continue
		}

		// Exact version match
		if node.Data.GetVersion() == rangeStr {
			return node
		}

		if semver.IsVersionInRange(node.Data.GetVersion(), rangeStr) {
			return node
		}
	}

	return nil
}

package parser

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func findPackageInUvGraph(graph *models.DependencyGraph[*models.Package], name, version string) *models.Package {
	for _, node := range graph.GetPackages() {
		if node.GetName() == name && node.GetVersion() == version {
			return node
		}
	}
	return nil
}

func TestUvGraphParserBasic(t *testing.T) {
	pm, err := parseUvPackageLockAsGraph("./fixtures/uv.lock", defaultParserConfigForTest)
	assert.Nil(t, err)

	assert.NotNil(t, pm)
	assert.NotNil(t, pm.DependencyGraph)
	assert.NotEmpty(t, pm.DependencyGraph.GetNodes())
	assert.Equal(t, 19, len(pm.GetPackages()))
}

func TestUvGraphParserDependencies(t *testing.T) {
	pm, err := parseUvPackageLockAsGraph("./fixtures/uv.lock", defaultParserConfigForTest)
	assert.Nil(t, err)

	djangoNode := findPackageInUvGraph(pm.DependencyGraph, "django", "3.2")
	assert.NotNil(t, djangoNode)

	djangoDeps := pm.DependencyGraph.GetDependencies(djangoNode)
	assert.Equal(t, 3, len(djangoDeps))

	depNames := []string{}
	for _, dep := range djangoDeps {
		depNames = append(depNames, dep.GetName())
	}

	expectedDeps := []string{
		"asgiref",
		"pytz",
		"sqlparse",
	}
	assert.ElementsMatch(t, expectedDeps, depNames)

	fastapiNode := findPackageInUvGraph(pm.DependencyGraph, "fastapi", "0.68.0")
	assert.NotNil(t, fastapiNode)

	fastapiDeps := pm.DependencyGraph.GetDependencies(fastapiNode)
	assert.Equal(t, 2, len(fastapiDeps))

	fastapiDepNames := []string{}
	for _, dep := range fastapiDeps {
		fastapiDepNames = append(fastapiDepNames, dep.GetName())
	}

	expectedFastapiDeps := []string{
		"pydantic",
		"starlette",
	}
	assert.ElementsMatch(t, expectedFastapiDeps, fastapiDepNames)
}

func TestUvGraphParserDependents(t *testing.T) {
	pm, err := parseUvPackageLockAsGraph("./fixtures/uv.lock", defaultParserConfigForTest)
	assert.Nil(t, err)

	asgirefNode := findPackageInUvGraph(pm.DependencyGraph, "asgiref", "3.8.1")
	assert.NotNil(t, asgirefNode)

	asgirefDependents := pm.DependencyGraph.GetDependents(asgirefNode)
	assert.Equal(t, 1, len(asgirefDependents))
	assert.Equal(t, "django", asgirefDependents[0].GetName())
}

func TestUvGraphParserPathToRoot(t *testing.T) {
	pm, err := parseUvPackageLockAsGraph("./fixtures/uv.lock", defaultParserConfigForTest)
	assert.Nil(t, err)

	asgirefNode := findPackageInUvGraph(pm.DependencyGraph, "asgiref", "3.8.1")
	assert.NotNil(t, asgirefNode)

	pathToRoot := pm.DependencyGraph.PathToRoot(asgirefNode)
	assert.Equal(t, 2, len(pathToRoot))
	assert.Equal(t, "asgiref", pathToRoot[0].GetName())
	assert.Equal(t, "django", pathToRoot[1].GetName())
}

func TestUvGraphParserVersions(t *testing.T) {
	pm, err := parseUvPackageLockAsGraph("./fixtures/uv.lock", defaultParserConfigForTest)
	assert.Nil(t, err)

	testCases := []struct {
		name     string
		version  string
		expected bool
	}{
		{"django", "3.2", true},
		{"fastapi", "0.68.0", true},
		{"asgiref", "3.8.1", true},
		{"django", "4.0", false},
		{"nonexistent", "1.0", false},
	}

	for _, tc := range testCases {
		pkg := findPackageInUvGraph(pm.DependencyGraph, tc.name, tc.version)
		if tc.expected {
			assert.NotNil(t, pkg, "Expected to find package %s version %s", tc.name, tc.version)
		} else {
			assert.Nil(t, pkg, "Expected not to find package %s version %s", tc.name, tc.version)
		}
	}
}

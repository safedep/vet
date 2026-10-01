package parser

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/models"
)

const spdxGitHubDependencyGraphDocument = `{
	"SPDXID": "SPDXRef-DOCUMENT",
	"spdxVersion": "SPDX-2.3",
	"dataLicense": "CC0-1.0",
	"name": "com.github.OrgXYZ/knowledge_graph",
	"documentNamespace": "https://github.com/OrgXYZ/knowledge_graph/dependency_graph/sbom-a83d8295",
	"creationInfo": {"created": "2023-08-18T13:05:12Z", "creators": ["Tool: GitHub.com-Dependency-Graph"]},
	"documentDescribes": ["SPDXRef-my-graph"],
	"packages": [
		{"SPDXID": "SPDXRef-my-graph", "name": "com.github.OrgXYZ/knowledge_graph",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:github/OrgXYZ/knowledge_graph"}]},
		{"SPDXID": "SPDXRef-pip-flake8", "name": "pip:flake8", "versionInfo": ">= 3.5.0"},
		{"SPDXID": "SPDXRef-actions-checkout", "name": "actions:actions/checkout", "versionInfo": "2",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:githubactions/actions/checkout@2"}]},
		{"SPDXID": "SPDXRef-npm-agent-base", "name": "npm:agent-base", "versionInfo": "4.3.0",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/agent-base@4.3.0"}]}
	],
	"relationships": [
		{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-my-graph", "relatedSpdxElement": "SPDXRef-pip-flake8"},
		{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-my-graph", "relatedSpdxElement": "SPDXRef-actions-checkout"},
		{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-pip-flake8", "relatedSpdxElement": "SPDXRef-npm-agent-base"}
	]
}`

func spdxTestDocument(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sbom.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	return path
}

func spdxParse(t *testing.T, body string) *models.PackageManifest {
	t.Helper()

	document := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"name": "test-document",
		"documentNamespace": "https://example.com/test-document",
		` + body + `
	}`

	manifest, err := parseSbomSpdxAsGraph(spdxTestDocument(t, document), &ParserConfig{})
	require.NoError(t, err)

	return manifest
}

// GetPackages iterates the dependency graph map when a graph is present, so it
// orders packages differently on every call. Look up within one snapshot.
func spdxFindPackage(packages []*models.Package, name string) *models.Package {
	idx := slices.IndexFunc(packages, func(pkg *models.Package) bool {
		return pkg.GetName() == name
	})
	if idx < 0 {
		return nil
	}

	return packages[idx]
}

// A document can name the same package twice at different versions, so this
// matches on both rather than looking up by name and then checking the version.
func spdxHasPackage(packages []*models.Package, name, version string) bool {
	return slices.ContainsFunc(packages, func(pkg *models.Package) bool {
		return pkg.GetName() == name && pkg.GetVersion() == version
	})
}

func TestParseSpdxSBOM(t *testing.T) {
	manifest, err := parseSbomSpdxAsGraph(spdxTestDocument(t, spdxGitHubDependencyGraphDocument),
		&ParserConfig{})
	require.NoError(t, err)

	packages := manifest.GetPackages()

	assert.Len(t, packages, 3)
	assert.Nil(t, spdxFindPackage(packages, "OrgXYZ/knowledge_graph"))

	assert.True(t, spdxHasPackage(packages, "flake8", "3.5.0"))
	assert.True(t, spdxHasPackage(packages, "actions/checkout", "2"))
	assert.True(t, spdxHasPackage(packages, "agent-base", "4.3.0"))
}

func TestParseSpdxSBOMDependencyGraph(t *testing.T) {
	manifest, err := parseSbomSpdxAsGraph(spdxTestDocument(t, spdxGitHubDependencyGraphDocument),
		&ParserConfig{})
	require.NoError(t, err)

	graph := manifest.DependencyGraph
	assert.True(t, graph.Present())

	packages := manifest.GetPackages()
	flake8 := spdxFindPackage(packages, "flake8")
	agentBase := spdxFindPackage(packages, "agent-base")
	require.NotNil(t, flake8)
	require.NotNil(t, agentBase)

	assert.True(t, graph.IsRoot(flake8))
	assert.True(t, graph.IsRoot(spdxFindPackage(packages, "actions/checkout")))
	assert.False(t, graph.IsRoot(agentBase))

	dependencies := graph.GetDependencies(flake8)
	require.Len(t, dependencies, 1)
	assert.Equal(t, "agent-base", dependencies[0].GetName())

	assert.Equal(t, []*models.Package{flake8}, graph.GetDependents(agentBase))
}

func TestParseSpdxSBOMWithoutDependencyRelationships(t *testing.T) {
	manifest := spdxParse(t, `
		"documentDescribes": ["SPDXRef-scan"],
		"packages": [
			{"SPDXID": "SPDXRef-scan", "name": "syft-scan"},
			{"SPDXID": "SPDXRef-lodash", "name": "npm:lodash", "versionInfo": "4.17.21"}
		]`)

	packages := manifest.GetPackages()
	assert.Len(t, packages, 1)
	assert.True(t, spdxHasPackage(packages, "lodash", "4.17.21"))

	assert.False(t, manifest.DependencyGraph.Present())
}

func TestParseSpdxSBOMWithoutDescribedElement(t *testing.T) {
	manifest := spdxParse(t, `
		"packages": [
			{"name": "npm:lodash", "versionInfo": "4.17.21"},
			{"SPDXID": "SPDXRef-axios", "name": "npm:axios", "versionInfo": "1.6.0"}
		]`)

	packages := manifest.GetPackages()
	assert.Len(t, packages, 2)
	assert.True(t, spdxHasPackage(packages, "lodash", "4.17.21"))
	assert.True(t, spdxHasPackage(packages, "axios", "1.6.0"))
}

// proj-a is described by the documentDescribes field, proj-b by an explicit
// relationship written the other way round. Both anchor the graph.
func TestParseSpdxSBOMWithMultipleDescribedElements(t *testing.T) {
	manifest := spdxParse(t, `
		"documentDescribes": ["SPDXRef-proj-a"],
		"packages": [
			{"SPDXID": "SPDXRef-proj-a", "name": "proj-a"},
			{"SPDXID": "SPDXRef-proj-b", "name": "proj-b"},
			{"SPDXID": "SPDXRef-lodash", "name": "npm:lodash", "versionInfo": "4.17.21"},
			{"SPDXID": "SPDXRef-axios", "name": "npm:axios", "versionInfo": "1.6.0"}
		],
		"relationships": [
			{"relationshipType": "DESCRIBED_BY", "spdxElementId": "SPDXRef-proj-b", "relatedSpdxElement": "SPDXRef-DOCUMENT"},
			{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-proj-a", "relatedSpdxElement": "SPDXRef-lodash"},
			{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-proj-b", "relatedSpdxElement": "SPDXRef-axios"}
		]`)

	packages := manifest.GetPackages()
	assert.Len(t, packages, 2)

	lodash := spdxFindPackage(packages, "lodash")
	axios := spdxFindPackage(packages, "axios")
	require.NotNil(t, lodash)
	require.NotNil(t, axios)

	assert.True(t, manifest.DependencyGraph.IsRoot(lodash))
	assert.True(t, manifest.DependencyGraph.IsRoot(axios))
}

func TestParseSpdxSBOMWithDependencyOfRelationship(t *testing.T) {
	manifest := spdxParse(t, `
		"documentDescribes": ["SPDXRef-myapp"],
		"packages": [
			{"SPDXID": "SPDXRef-myapp", "name": "myapp"},
			{"SPDXID": "SPDXRef-lodash", "name": "npm:lodash", "versionInfo": "4.17.21"}
		],
		"relationships": [
			{"relationshipType": "DEPENDENCY_OF", "spdxElementId": "SPDXRef-lodash", "relatedSpdxElement": "SPDXRef-myapp"}
		]`)

	packages := manifest.GetPackages()
	require.Len(t, packages, 1)

	assert.True(t, manifest.DependencyGraph.Present())
	assert.True(t, manifest.DependencyGraph.IsRoot(packages[0]))
}

func TestParseSpdxSBOMWithUnaddressableRelationships(t *testing.T) {
	manifest := spdxParse(t, `
		"externalDocumentRefs": [
			{"externalDocumentId": "DocumentRef-ext", "spdxDocument": "https://example.com/ext",
				"checksum": {"algorithm": "SHA1", "checksumValue": "d6a770ba38583ed4bb4525bd96e50461655d2758"}}
		],
		"packages": [
			{"name": "npm:ghost", "versionInfo": "1.0.0"},
			{"SPDXID": "SPDXRef-alpha", "name": "npm:alpha", "versionInfo": "1.0.0"},
			{"SPDXID": "SPDXRef-beta", "name": "npm:beta", "versionInfo": "2.0.0"}
		],
		"relationships": [
			{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-alpha", "relatedSpdxElement": "NOASSERTION"},
			{"relationshipType": "DEPENDS_ON", "spdxElementId": "SPDXRef-alpha", "relatedSpdxElement": "DocumentRef-ext:SPDXRef-beta"}
		]`)

	packages := manifest.GetPackages()
	assert.Len(t, packages, 3)

	alpha := spdxFindPackage(packages, "alpha")
	require.NotNil(t, alpha)

	assert.Empty(t, manifest.DependencyGraph.GetDependencies(alpha))
	assert.False(t, manifest.DependencyGraph.Present())
}

func TestParseSpdxSBOMWithInvalidDocument(t *testing.T) {
	_, err := parseSbomSpdxAsGraph(spdxTestDocument(t, `not json`), &ParserConfig{})
	assert.Error(t, err)
}

func TestParseSpdxSBOMFixtures(t *testing.T) {
	cases := []struct {
		path             string
		expectedPackages int
		expectedName     string
		expectedVersion  string
	}{
		{"./fixtures/requests_psf_2ee5b0b01.json", 22, "pytest", "2.8.0"},
		{"./fixtures/osv-scanner_google_3cab6.json", 162, "activesupport", "7.0.7"},
		{"./fixtures/janusgraph_oss_2dc3a123d9.json", 300, "commons-io:commons-io", "2.11.0"},
	}

	for _, test := range cases {
		t.Run(filepath.Base(test.path), func(t *testing.T) {
			manifest, err := parseSbomSpdxAsGraph(test.path, &ParserConfig{})
			require.NoError(t, err)

			packages := manifest.GetPackages()
			assert.Len(t, packages, test.expectedPackages)
			assert.True(t, manifest.DependencyGraph.Present())
			assert.True(t, spdxHasPackage(packages, test.expectedName, test.expectedVersion))
		})
	}
}

// The Dependency Graph API relates every package to the repository itself, so the
// graph it produces is one level deep.
func TestParseSpdxSBOMFixtureRootsAreDirectDependencies(t *testing.T) {
	manifest, err := parseSbomSpdxAsGraph("./fixtures/requests_psf_2ee5b0b01.json", &ParserConfig{})
	require.NoError(t, err)

	for _, pkg := range manifest.GetPackages() {
		assert.True(t, manifest.DependencyGraph.IsRoot(pkg), pkg.GetName())
	}
}

func TestSpdxExtractPackage(t *testing.T) {
	cases := []struct {
		name            string
		packageName     string
		packageVersion  string
		purl            string
		expectedName    string
		expectedVersion string
		expectedError   bool
	}{
		{name: "scoped npm name", packageName: "npm:acme/zeta", packageVersion: "4.17.21", expectedName: "acme/zeta", expectedVersion: "4.17.21"},
		{name: "maven group in type", packageName: "maven:org.acme:lib", packageVersion: "1.1.0-SNAPSHOT", expectedName: "org.acme:lib", expectedVersion: "1.1.0-SNAPSHOT"},
		{name: "action name", packageName: "actions:actions/checkout", packageVersion: "2", expectedName: "actions/checkout", expectedVersion: "2"},
		{name: "go module path", packageName: "go:github.com/spf13/cobra", packageVersion: "1.8.0", expectedName: "github.com/spf13/cobra", expectedVersion: "1.8.0"},
		{name: "name without a group", packageName: "pypi:alpha", packageVersion: "1.0.0rc1", expectedName: "alpha", expectedVersion: "1.0.0rc1"},

		{name: "purl over the name", packageName: "npm:acme/iota", packageVersion: "9.9.9", purl: "pkg:npm/iota@2.0.0", expectedName: "iota", expectedVersion: "2.0.0"},
		{name: "unreadable purl", packageName: "npm:acme/lambda", packageVersion: "1.0.0", purl: "not-a-purl", expectedName: "acme/lambda", expectedVersion: "1.0.0"},

		{name: "unsupported ecosystem", packageName: "conda:numpy", packageVersion: "1.26.0", expectedError: true},
		{name: "empty name", packageName: "pip:", packageVersion: "1.0.0", expectedError: true},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			spdxPackage := &spdx.Package{
				PackageName:    test.packageName,
				PackageVersion: test.packageVersion,
			}

			if test.purl != "" {
				spdxPackage.PackageExternalReferences = []*spdx.PackageExternalReference{
					{RefType: "purl", Locator: test.purl},
				}
			}

			pkg, err := spdxExtractPackage(spdxPackage)
			if test.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedName, pkg.GetName())
			assert.Equal(t, test.expectedVersion, pkg.GetVersion())
		})
	}
}

package parser

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

var defaultParserConfigForTest = &ParserConfig{}

func findPackageInGraph(graph *models.DependencyGraph[*models.Package], name, version string) *models.Package {
	for _, node := range graph.GetPackages() {
		if node.GetName() == name && node.GetVersion() == version {
			return node
		}
	}

	return nil
}

func TestNpmGraphParserBasic(t *testing.T) {
	pm, err := parseNpmPackageLockAsGraph("./fixtures/package-lock-graph.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	assert.NotNil(t, pm)
	assert.NotNil(t, pm.DependencyGraph)
	assert.NotEmpty(t, pm.DependencyGraph.GetNodes())
}

func TestPackageJsonOnlyDevDependencies(t *testing.T) {
	pm, err := parseNpmPackageJsonAsGraph("./fixtures/package-json-with-only-dev-dependencies.json",
		&ParserConfig{IncludeDevDependencies: true})
	assert.Nil(t, err)

	assert.NotNil(t, pm)
	assert.NotNil(t, pm.DependencyGraph)
	assert.NotEmpty(t, pm.DependencyGraph.GetNodes())
	assert.Equal(t, 1, len(pm.GetPackages()))
}

func TestNpmGraphParserDependencies(t *testing.T) {
	pm, err := parseNpmPackageLockAsGraph("./fixtures/package-lock-graph.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	aNode := findPackageInGraph(pm.DependencyGraph, "@aws-sdk/client-s3", "3.478.0")
	assert.NotNil(t, aNode)

	aNodeDependencies := pm.DependencyGraph.GetDependencies(aNode)
	assert.NotEmpty(t, aNodeDependencies)
	assert.Equal(t, 58, len(aNodeDependencies))

	dependencyNames := []string{}
	for _, node := range aNodeDependencies {
		dependencyNames = append(dependencyNames, node.GetName())
	}

	expectedDependencyNames := []string{
		"@aws-sdk/middleware-user-agent",
		"@aws-sdk/middleware-ssec",
		"@aws-sdk/client-sts",
		"@aws-crypto/sha256-js",
		"@aws-sdk/signature-v4-multi-region",
		"@smithy/middleware-serde",
		"@smithy/fetch-http-handler",
		"@aws-sdk/xml-builder",
		"@aws-sdk/middleware-expect-continue",
		"@smithy/node-config-provider",
		"@aws-sdk/util-user-agent-browser",
		"@aws-sdk/util-endpoints",
		"@aws-sdk/middleware-logger",
		"@smithy/util-retry",
		"@smithy/util-defaults-mode-node",
		"@smithy/md5-js",
		"@aws-sdk/util-user-agent-node",
		"@aws-sdk/middleware-recursion-detection",
		"@aws-sdk/middleware-location-constraint",
		"@smithy/util-endpoints",
		"@smithy/url-parser",
		"@smithy/middleware-retry",
		"@smithy/middleware-stack",
		"@smithy/eventstream-serde-node",
		"@smithy/eventstream-serde-browser",
		"@aws-sdk/middleware-signing",
		"@smithy/util-stream",
		"@smithy/node-http-handler",
		"@smithy/protocol-http",
		"@aws-sdk/middleware-host-header",
		"@aws-crypto/sha256-browser",
		"@smithy/middleware-endpoint",
		"@aws-sdk/types",
		"@aws-sdk/region-config-resolver",
		"@aws-sdk/middleware-sdk-s3",
		"@smithy/util-waiter",
		"@smithy/config-resolver",
		"@aws-sdk/middleware-flexible-checksums",
		"fast-xml-parser",
		"@aws-crypto/sha1-browser",
		"@smithy/util-base64",
		"@smithy/middleware-content-length",
		"@aws-sdk/middleware-bucket-endpoint",
		"@aws-sdk/core",
		"@smithy/util-body-length-node",
		"@smithy/types",
		"@smithy/hash-stream-node",
		"@smithy/eventstream-serde-config-resolver",
		"@smithy/util-utf8",
		"@smithy/smithy-client",
		"@smithy/hash-node",
		"@smithy/util-defaults-mode-browser",
		"@smithy/invalid-dependency",
		"@smithy/hash-blob-browser",
		"tslib",
		"@smithy/util-body-length-browser",
		"@smithy/core",
		"@aws-sdk/credential-provider-node",
	}

	assert.ElementsMatch(t, expectedDependencyNames, dependencyNames)
}

func TestNpmGraphParserDependents(t *testing.T) {
	pm, err := parseNpmPackageLockAsGraph("./fixtures/package-lock-graph.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	bNode := findPackageInGraph(pm.DependencyGraph, "tslib", "1.14.1")
	assert.NotNil(t, bNode)

	bNodeDependents := pm.DependencyGraph.GetDependents(bNode)
	assert.NotEmpty(t, bNodeDependents)
	assert.Equal(t, 18, len(bNodeDependents))

	bNodeDependentNames := []string{}
	for _, node := range bNodeDependents {
		bNodeDependentNames = append(bNodeDependentNames, node.GetName())
	}

	expectedDependentNames := []string{
		"@aws-crypto/crc32c",
		"@aws-crypto/supports-web-crypto",
		"@aws-crypto/supports-web-crypto",
		"@aws-crypto/supports-web-crypto",
		"@aws-crypto/supports-web-crypto",
		"@aws-crypto/supports-web-crypto",
		"@aws-crypto/sha256-js",
		"@aws-crypto/sha256-js",
		"@aws-crypto/sha256-js",
		"@aws-crypto/sha256-js",
		"@aws-crypto/sha256-browser",
		"@aws-crypto/sha256-browser",
		"@aws-crypto/sha256-browser",
		"@aws-crypto/sha256-browser",
		"@aws-crypto/ie11-detection",
		"@aws-crypto/sha1-browser",
		"@aws-crypto/crc32",
		"@aws-crypto/util",
	}

	assert.ElementsMatch(t, expectedDependentNames, bNodeDependentNames)
}

func TestNpmGraphParserPathToRootFromRoot(t *testing.T) {
	pm, err := parseNpmPackageLockAsGraph("./fixtures/package-lock-graph.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	aNode := findPackageInGraph(pm.DependencyGraph, "@aws-sdk/client-s3", "3.478.0")
	assert.NotNil(t, aNode)

	aNodeToRoot := pm.DependencyGraph.PathToRoot(aNode)
	assert.Equal(t, 1, len(aNodeToRoot))
	assert.Equal(t, "@aws-sdk/client-s3", aNodeToRoot[0].GetName())
}

func TestNpmGraphParserPathToRootFromDependent(t *testing.T) {
	pm, err := parseNpmPackageLockAsGraph("./fixtures/package-lock-graph.json", defaultParserConfigForTest)
	assert.Nil(t, err)

	bNode := findPackageInGraph(pm.DependencyGraph, "tslib", "1.14.1")
	assert.NotNil(t, bNode)

	bNodeToRoot := pm.DependencyGraph.PathToRoot(bNode)
	assert.Equal(t, 4, len(bNodeToRoot))
	assert.Equal(t, "tslib", bNodeToRoot[0].GetName())
	assert.Equal(t, "@aws-crypto/sha256-js", bNodeToRoot[1].GetName())
	assert.Equal(t, "@aws-sdk/client-sts", bNodeToRoot[2].GetName())
	assert.Equal(t, "@aws-sdk/client-s3", bNodeToRoot[3].GetName())
}

func TestNpmVersionConstraintResolveVersion(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		output string
		err    error
	}{
		{
			name:   "resolved version",
			input:  "1.2.3",
			output: "1.2.3",
		},
		{
			name:   "semver with tilde",
			input:  "~1.2.3",
			output: "1.2.3",
		},
		{
			name:   "semver with tilde space",
			input:  "~ 1.2.3",
			output: "1.2.3",
		},
		{
			name:   "semver with greater equal",
			input:  ">=1.2.3",
			output: "1.2.3",
		},
		{
			name:   "non-semver version",
			input:  "latest",
			output: "latest",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			version, err := npmVersionConstraintResolveVersion(test.input)
			if test.err != nil {
				assert.Error(t, err)
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.Equal(t, test.output, version)
			}
		})
	}
}

func TestNpmPackageJsonDependencies(t *testing.T) {
	pm, err := parseNpmPackageJsonAsGraph("./fixtures/package.json", defaultParserConfigForTest)
	assert.Nil(t, err)
	assert.NotNil(t, pm)

	actualPackages := map[string]string{}
	for _, pkg := range pm.GetPackages() {
		actualPackages[pkg.GetName()] = pkg.GetVersion()
	}

	expectedPackages := map[string]string{
		"accepts":             "1.3.8",
		"array-flatten":       "1.1.1",
		"body-parser":         "1.20.1",
		"content-disposition": "0.5.4",
		"content-type":        "1.0.4",
		"cookie":              "0.5.0",
		"cookie-signature":    "1.0.6",
		"debug":               "2.6.9",
		"depd":                "2.0.0",
		"encodeurl":           "1.0.2",
		"escape-html":         "1.0.3",
		"etag":                "1.8.1",
		"finalhandler":        "1.2.0",
		"fresh":               "0.5.2",
		"http-errors":         "2.0.0",
		"merge-descriptors":   "1.0.1",
		"methods":             "1.1.2",
		"on-finished":         "2.4.1",
		"parseurl":            "1.3.3",
		"path-to-regexp":      "0.1.7",
		"proxy-addr":          "2.0.7",
		"qs":                  "6.11.0",
		"range-parser":        "1.2.1",
		"safe-buffer":         "5.2.1",
		"send":                "0.18.0",
		"serve-static":        "1.15.0",
		"setprototypeof":      "1.2.0",
		"statuses":            "2.0.1",
		"type-is":             "1.6.18",
		"utils-merge":         "1.0.1",
		"vary":                "1.1.2",
	}

	for pkg, ver := range expectedPackages {
		assert.Contains(t, actualPackages, pkg)
		assert.Equal(t, ver, actualPackages[pkg])
	}
}

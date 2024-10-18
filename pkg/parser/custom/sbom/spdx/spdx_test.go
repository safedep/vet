package spdx

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSpdxSBOM(t *testing.T) {
	tempFile, _ := os.CreateTemp("", "sbom_*.json")

	defer os.Remove(tempFile.Name())
	sbomContent := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"creationInfo": {
		  "created": "2023-08-18T13:05:12Z",
		  "creators": [
			"Tool: GitHub.com-Dependency-Graph"
		  ],
		  "comment": "Exact versions could not be resolved for some packages. For more information: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#dependencies-included."
		},
		"name": "com.github.OrgXYZ/knowledge_graph",
		"dataLicense": "CC0-1.0",
		"documentDescribes": [
		  "SPDXRef-com.github.OrgXYZ-my-graph"
		],
		"documentNamespace": "https://github.com/OrgXYZ/knowledge_graph/dependency_graph/sbom-a83d82956179e7d1",
		"packages": [
		  {
			"SPDXID": "SPDXRef-com.github.OrgXYZ-my-graph",
			"name": "com.github.OrgXYZ/knowledge_graph",
			"versionInfo": "",
			"downloadLocation": "git+https://github.com/OrgXYZ/knowledge_graph",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION",
			"externalRefs": [
			  {
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType": "purl",
				"referenceLocator": "pkg:github/OrgXYZ/knowledge_graph"
			  }
			]
		  },
		  {
			"SPDXID": "SPDXRef-pip-flake8",
			"name": "pip:flake8",
			"versionInfo": ">= 3.5.0",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-mock",
			"name": "pip:mock",
			"versionInfo": ">= 2.0.0",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-pip",
			"name": "pip:pip",
			"versionInfo": "",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-pyhamcrest",
			"name": "pip:pyhamcrest",
			"versionInfo": ">= 1.9.0",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-pytest",
			"name": "pip:pytest",
			"versionInfo": ">= 4.2.1",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-pytest-runner",
			"name": "pip:pytest-runner",
			"versionInfo": ">= 4.2",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-tox",
			"name": "pip:tox",
			"versionInfo": "",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-tox-pyenv",
			"name": "pip:tox-pyenv",
			"versionInfo": "",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-wheel",
			"name": "pip:wheel",
			"versionInfo": "",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-pip-nose",
			"name": "pip:nose",
			"versionInfo": "",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION"
		  },
		  {
			"SPDXID": "SPDXRef-actions-actions-checkout-2",
			"name": "actions:actions/checkout",
			"versionInfo": "2",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION",
			"externalRefs": [
			  {
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator": "pkg:githubactions/actions/checkout@2",
				"referenceType": "purl"
			  }
			]
		  },
		  {
			"SPDXID": "SPDXRef-actions-actions-setup-python-2",
			"name": "actions:actions/setup-python",
			"versionInfo": "2",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION",
			"externalRefs": [
			  {
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator": "pkg:githubactions/actions/setup-python@2",
				"referenceType": "purl"
			  }
			]
		  },
		  {
			"SPDXID": "SPDXRef-actions-safedep-pacman-main",
			"name": "actions:safedep/pacman",
			"versionInfo": "main",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"supplier": "NOASSERTION",
			"externalRefs": [
			  {
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator": "pkg:githubactions/safedep/pacman@main",
				"referenceType": "purl"
			  }
			]
		  },
		  {
			"SPDXID": "SPDXRef-npm-agent-base-4.3.0",
			"name": "npm:agent-base",
			"versionInfo": "4.3.0",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT",
			"supplier": "NOASSERTION",
			"externalRefs": [
			  {
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator": "pkg:npm/agent-base@4.3.0",
				"referenceType": "purl"
			  }
			]
		  },
		  {
			"SPDXID": "SPDXRef-npm-ajv-6.10.2",
			"name": "npm:ajv",
			"versionInfo": "6.10.2",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT",
			"supplier": "NOASSERTION",
			"externalRefs": [
			  {
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator": "pkg:npm/ajv@6.10.2",
				"referenceType": "purl"
			  }
			]
		  }
		],
		"relationships": [
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-flake8"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-mock"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-pip"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-pyhamcrest"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-pytest"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-pytest-runner"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-tox"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-tox-pyenv"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-wheel"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-pip-nose"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-actions-actions-checkout-2"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-actions-actions-setup-python-2"
		  },
		  {
			"relationshipType": "DEPENDS_ON",
			"spdxElementId": "SPDXRef-com.github.OrgXYZ-my-graph",
			"relatedSpdxElement": "SPDXRef-actions-safedep-pacman-main"
		  }
		]
	  }`

	err := os.WriteFile(tempFile.Name(), []byte(sbomContent), 0644)
	assert.Nil(t, err)

	packages, err := Parse(tempFile.Name())

	assert.Nil(t, err)
	assert.Len(t, packages, 15)
	assert.Equal(t, "flake8", packages[0].Name)
	assert.Equal(t, "mock", packages[1].Name)
}

type expectedResult struct {
	total_pkgs int
}

func TestGetDependencies(t *testing.T) {
	tests := []struct {
		filepath string
		expected expectedResult
	}{
		{
			filepath: "./fixtures/requests_psf_2ee5b0b01.json", // Path to your test file
			expected: expectedResult{
				total_pkgs: 22,
			},
		},
		{
			filepath: "./fixtures/osv-scanner_google_3cab6.json",
			expected: expectedResult{
				total_pkgs: 162,
			},
		},
		{
			filepath: "./fixtures/janusgraph_oss_2dc3a123d9.json",
			expected: expectedResult{
				total_pkgs: 300,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.filepath, func(t *testing.T) {
			pkgs_doc, err := parse2PackageDetailsDoc(test.filepath)

			assert.Nil(t, err)
			assert.Len(t, pkgs_doc.PackageDetails, test.expected.total_pkgs)

			for _, pd := range pkgs_doc.PackageDetails {
				for _, ch := range []string{":"} {
					assert.False(t, strings.HasPrefix(pd.Name, ch),
						fmt.Sprintf("Name should not start with %s", ch))
					assert.False(t, strings.HasSuffix(pd.Name, ch),
						fmt.Sprintf("Name should not end with %s", ch))
					assert.False(t, strings.HasSuffix(pd.Name, ch),
						fmt.Sprintf("Name should not end with %s", ch))

					assert.True(t, len(pd.Name) > 0, "Package Name can not be empty")
					assert.True(t, len(pd.Ecosystem) > 0, "Ecosystem can not be empty")
					assert.True(t, len(pd.CompareAs) > 0, "CompareAs can not be empty")

					assert.True(t, len(pd.Version) >= 0, "Version can not be empty")

					assert.NotNil(t, pd.SpdxRef)
					if pd.Version != "0.0.0" {
						assert.True(t, strings.Contains(pd.SpdxRef.PackageVersion, pd.Version),
							fmt.Sprintf("Incorrect version %s should be part of %s",
								pd.SpdxRef.PackageVersion, pd.Version))
					}
				}
			}
		})
	}
}

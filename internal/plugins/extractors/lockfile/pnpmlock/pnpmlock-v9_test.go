// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pnpmlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/graphtest"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/pnpmlock"
)

func TestExtractor_Extract_v9(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.v9.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/one-package.v9.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/one-package-dev.v9.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/scoped-packages.v9.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies.v9.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.11.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies.v9.yaml", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies advanced",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-advanced.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@eslint-community/eslint-utils",
					Version:    "4.4.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@eslint/eslintrc",
					Version:    "2.1.4",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 32),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 36),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 47),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 57),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 67),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 76),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "debug",
					Version:    "4.3.4",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 82),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.57.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 91),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 96),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 100),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 104),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "typescript",
					Version:    "4.9.5",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.v9.yaml", 110),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-versions.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "uuid",
					Version:    "8.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-versions.v9.yaml", 20),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-versions.v9.yaml", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "11.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-versions.v9.yaml", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/commits.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ansi-regex",
					Version:  "6.0.1",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v9.yaml", 20),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "02fa893d619d3da85411acc8fd4e2eea0e95a9d9",
						Repo:   "https://github.com/chalk/ansi-regex",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number",
					Version:  "7.0.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v9.yaml", 25),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "98e8ff1da1a89f93d1397a24d7413ed15421c139",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "mixed groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mixed-groups.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "ansi-regex",
					Version:    "5.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/mixed-groups.v9.yaml", 25),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/mixed-groups.v9.yaml", 33),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "is-number",
					Version:    "7.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/mixed-groups.v9.yaml", 29),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multi document",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multi-document.v9.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@pnpm/exe",
					Version:    "11.9.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multi-document.v9.yaml", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.11.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multi-document.v9.yaml", 33),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := pnpmlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess), graphtest.IgnoreGraph); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

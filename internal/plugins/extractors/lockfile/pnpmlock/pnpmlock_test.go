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
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/graphtest"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/pnpmlock"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "pnpm-lock.yaml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pnpm-lock.yaml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pnpm-lock.yaml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/pnpm-lock.yaml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.pnpm-lock.yaml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "foo/node_modules/bar/pnpn-lock.yaml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pnpmlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pnpmlock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid yaml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-yaml.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "invalid dep path",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-path.yaml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid dependency path"},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/invalid-path.yaml", 11),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			// Regression test: a malformed scoped dependency path such as
			// "/@x" (which splits into ["", "@x"]) previously caused a
			// slice-bounds panic when joining the scope and name. It should
			// now be handled gracefully and simply skipped (no version).
			Name: "scoped dep path without version does not panic",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-path-no-version.yaml",
			},
			WantErr: nil,
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/scoped-path-no-version.yaml", 11),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "invalid dep paths (first error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-paths.yaml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid dependency path: invalidpath1"},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/invalid-paths.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "invalid dep paths (second error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-paths.yaml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid dependency path: invalidpath2"},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/invalid-paths.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "missing packages key",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-packages.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/one-package.yaml", 11),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package v6 lockfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-v6-lockfile.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/one-package-v6-lockfile.yaml", 10),
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
				Path: "testdata/one-package-dev.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/one-package-dev.yaml", 11),
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
				Path: "testdata/scoped-packages.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/scoped-packages.yaml", 11),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages v6 lockfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages-v6-lockfile.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.57.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/scoped-packages-v6-lockfile.yaml", 10),
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
				Path: "testdata/peer-dependencies.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies.yaml", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies.yaml", 21),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer_dependencies_v6",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-v6.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "js-tokens",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-v6.yaml", 14),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "loose-envify",
					Version:    "1.4.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-v6.yaml", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "react-dom",
					Version:    "18.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-v6.yaml", 25),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "react",
					Version:    "18.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-v6.yaml", 35),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "scheduler",
					Version:    "0.23.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-v6.yaml", 42),
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
				Path: "testdata/peer-dependencies-advanced.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 44),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 64),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 83),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 88),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.13.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 109),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint-utils",
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 127),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.10.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 137),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced.yaml", 181),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer_dependencies_advanced_v6",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-advanced-v6.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "js-tokens",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-v6.yaml", 14),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "loose-envify",
					Version:    "1.4.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-v6.yaml", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "react-dom",
					Version:    "18.3.0-canary-ab31a9ed2-20230824",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-v6.yaml", 25),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "react",
					Version:    "18.3.0-canary-ab31a9ed2-20230824",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-v6.yaml", 35),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "scheduler",
					Version:    "0.24.0-canary-ab31a9ed2-20230824",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-v6.yaml", 42),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer_dependencies_advanced_rc_v6",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-advanced-rc-v6.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "js-tokens",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-rc-v6.yaml", 14),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "loose-envify",
					Version:    "1.4.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-rc-v6.yaml", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "react-dom",
					Version:    "18.0.0-rc.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-rc-v6.yaml", 25),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "react",
					Version:    "18.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-rc-v6.yaml", 35),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "scheduler",
					Version:    "0.21.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/peer-dependencies-advanced-rc-v6.yaml", 42),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-packages.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "aws-sdk",
					Version:    "2.1087.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 11),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "base64-js",
					Version:    "1.5.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "buffer",
					Version:    "4.9.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 30),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "events",
					Version:    "1.1.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 38),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ieee754",
					Version:    "1.1.13",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 43),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "isarray",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 47),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "jmespath",
					Version:    "0.16.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 51),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "punycode",
					Version:    "1.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 56),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "querystring",
					Version:    "0.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 60),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "sax",
					Version:    "1.2.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 66),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "url",
					Version:    "0.10.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 70),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "3.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 77),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xml2js",
					Version:    "0.4.19",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 83),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "9.0.7",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-packages.yaml", 90),
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
				Path: "testdata/multiple-versions.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "uuid",
					Version:    "3.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-versions.yaml", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-versions.yaml", 19),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "9.0.7",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/multiple-versions.yaml", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "tarball",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/tarball.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@my-org/my-package",
					Version:    "3.2.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/tarball.yaml", 10),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "exotic",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/exotic.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "foo",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 10),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@foo/bar",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 11),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.1.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@foo/bar",
					Version:    "1.1.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.3.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 16),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.4.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/exotic.yaml", 17),
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
				Path: "testdata/commits.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "my-bitbucket-package",
					Version:  "1.0.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.yaml", 14),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "6104ae42cd32c3d724036d3964678f197b2c9cdb",
						Repo:   "https://bitbucket.org/my-org/my-bitbucket-project",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "@my-scope/my-package",
					Version:  "1.0.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.yaml", 20),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "267087851ad5fac92a184749c27cd539e2fc862e",
						Repo:   "https://github.com/my-org/my-package",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "@my-scope/my-other-package",
					Version:  "1.0.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.yaml", 28),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "fbfc962ab51eb1d754749b68c064460221fbd689",
						Repo:   "https://github.com/my-org/my-other-package",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "faker-parser",
					Version:  "0.0.1",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.yaml", 34),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
						Repo:   "https://github.com/my-org/faker-parser",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "mocks",
					Version:  "20.0.1",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.yaml", 42),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "590f321b4eb3f692bb211bd74e22947639a6f79d",
						Repo:   "https://github.com/my-org/mocks",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "my-file-package",
					Version:    "0.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/files.yaml", 10),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "a-local-package",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/files.yaml", 16),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "a-nested-local-package",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/files.yaml", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "one-up",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/files.yaml", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "one-up-with-peer",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/files.yaml", 34),
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
			extr, err := pnpmlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pnpmlock.New: %v", err)
			}

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

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

package bunlock_test

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

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/bunlock"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/graphtest"
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
			inputPath: "bun.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/bun.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/bun.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/bun.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.bun.lock",
			want:      false,
		},
		{
			name:      "",
			inputPath: "foo/node_modules/bar/bun.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := bunlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("bunlock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	loc := extractor.LocationFromPathAndLine
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json5",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.json5",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/one-package.json5", 12),
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
				Path: "testdata/one-package-dev.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/one-package-dev.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package with bad tuple (first error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/bad-tuple.json5",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract 'wrappy-bad1'"},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/bad-tuple.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package with bad tuple (second error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/bad-tuple.json5",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract 'wrappy-bad2'"},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/bad-tuple.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/two-packages.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/two-packages.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "same package in different groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/same-package-different-groups.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/same-package-different-groups.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/same-package-different-groups.json5", 17),
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
				Path: "testdata/scoped-packages.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages mixed",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages-mixed.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@babel/code-frame",
					Version:    "7.26.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-validator-identifier",
					Version:    "7.25.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "js-tokens",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 19),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "picocolors",
					Version:    "1.1.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 21),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 23),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-package.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					Version:    "8.14.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/optional-package.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "fsevents",
					Version:    "0.3.8",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/optional-package.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "nan",
					Version:    "2.22.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/optional-package.json5", 19),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies implicit",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-implicit.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-implicit.json5", 14),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.14.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-implicit.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies explicit",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-explicit.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-explicit.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.14.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-explicit.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "ansi-styles",
					Version:    "4.3.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 16),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "chalk",
					Version:    "4.1.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-convert",
					Version:    "2.0.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 20),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-name",
					Version:    "1.1.4",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "2.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 30),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 32),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies with duplicate versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies-dup.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "ansi-styles",
					Version:    "4.3.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 16),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "chalk",
					Version:    "4.1.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-convert",
					Version:    "2.0.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 20),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-name",
					Version:    "1.1.4",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "2.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "alias",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/alias.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "6.1.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 19),
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
				Path: "testdata/commits.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@babel/helper-plugin-utils",
					Version:    "7.26.5",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-string-parser",
					Version:    "7.25.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-validator-identifier",
					Version:    "7.25.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/parser",
					Version:    "7.26.5",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/types",
					Version:    "7.26.5",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 30),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "@prettier/sync",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 32),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "527e8ce",
						Repo:   "https://github.com/prettier/prettier-synchronized",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "babel-preset-php",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 34),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1ae6dc1267500360b411ec711b8aeac8c68b2246",
						Repo:   "https://gitlab.com/kornelski/babel-preset-php",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 36),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "98e8ff1",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 38),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac058",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 40),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "b7aef34",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "jquery",
					Version:    "3.7.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 42),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "lodash",
					Version:    "1.3.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 44),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "make-synchronized",
					Version:    "0.2.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 46),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "php-parser",
					Version:    "2.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 48),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "prettier",
					Version:    "3.4.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 50),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "raven-js",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 52),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "91ef2d4",
						Repo:   "https://github.com/getsentry/raven-js",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "slick-carousel",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/commits.json5", 54),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "fc6f7d8",
						Repo:   "https://github.com/brianfryer/slick",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "stopwords",
					Version:    "0.0.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 56),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "etag",
					Version:    "",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/files.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "lodash",
					Version:    "1.3.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/files.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "sample from blog post",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/blog-sample.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "uWebSockets.js",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: loc("testdata/blog-sample.json5", 11),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "6609a88",
						Repo:   "https://github.com/uNetworking/uWebSockets.js",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "url_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/urls.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@solidjs/meta",
					Version:    "0.29.4",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/urls.json5", 20),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@solidjs/start",
					Version:    "",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/urls.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrangler",
					Version:    "",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/urls.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ws",
					Version:    "8.21.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/urls.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "path-to-regexp",
					Version:    "6.3.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/urls.json5", 28),
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
			extr, err := bunlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("bunlock.New: %v", err)
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

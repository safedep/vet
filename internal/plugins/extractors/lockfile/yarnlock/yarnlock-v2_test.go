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

package yarnlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/graphtest"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/yarnlock"
)

func TestExtractor_Extract_v2(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.v2.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "balanced-match",
					Version:  "1.0.2",
					Location: extractor.LocationFromPathAndLine("testdata/one-package.v2.lock", 8),
					PURLType: purl.TypeNPM,
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "compare-func",
					Version:  "2.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "concat-map",
					Version:  "0.0.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.v2.lock", 18),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with quotes",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-quotes.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "compare-func",
					Version:  "2.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-quotes.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "concat-map",
					Version:  "0.0.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-quotes.v2.lock", 18),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-versions.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "debug",
					Version:  "4.3.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-versions.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "debug",
					Version:  "2.6.9",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-versions.v2.lock", 20),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "debug",
					Version:  "3.2.7",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-versions.v2.lock", 29),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@babel/cli",
					Version:  "7.16.8",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/scoped-packages.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "@babel/code-frame",
					Version:  "7.16.7",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/scoped-packages.v2.lock", 35),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "@babel/compat-data",
					Version:  "7.16.8",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/scoped-packages.v2.lock", 44),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with prerelease",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-prerelease.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@nicolo-ribaudo/chokidar-2",
					Version:  "2.1.8-no-fsevents.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-prerelease.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "gensync",
					Version:  "1.0.0-beta.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-prerelease.v2.lock", 15),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with build string",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-build-string.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "domino",
					Version:  "2.1.6+git",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/with-build-string.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
						Repo:   "https://github.com/angular/domino",
					},
				},
				{
					Name:     "tslib",
					Version:  "2.6.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-build-string.v2.lock", 15),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/commits.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@my-scope/my-first-package",
					Version:  "0.0.6",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0b824c650d3a03444dbcf2b27a5f3566f6e41358",
						Repo:   "https://github.com/my-org/my-first-package",
					},
				},
				{
					Name:     "my-second-package",
					Version:  "0.2.2",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 12),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "59e2127b9f9d4fda5f928c4204213b3502cd5bb0",
						Repo:   "https://github.com/my-org/my-second-package",
					},
				},
				{
					Name:     "@typegoose/typegoose",
					Version:  "7.2.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 21),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3ed06e5097ab929f69755676fee419318aaec73a",
						Repo:   "https://github.com/typegoose/typegoose",
					},
				},
				{
					Name:     "vuejs",
					Version:  "2.5.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 37),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0948d999f2fddf9f90991956493f976273c5da1f",
						Repo:   "https://github.com/vuejs/vue",
					},
				},
				{
					Name:     "my-third-package",
					Version:  "0.16.1-dev",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 45),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5675a0aed98e067ff6ecccc5ac674fe8995960e0",
						Repo:   "https://github.com/my-org/my-third-package",
					},
				},
				{
					Name:     "my-node-sdk",
					Version:  "1.1.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 50),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "053dea9e0b8af442d8f867c8e690d2fb0ceb1bf5",
						Repo:   "https://github.com/my-org/my-node-sdk",
					},
				},
				{
					Name:     "is-really-great",
					Version:  "1.0.0",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPathAndLine("testdata/commits.v2.lock", 58),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "191eeef50c584714e1fb8927d17ee72b3b8c97c4",
						Repo:   "https://github.com/my-org/is-really-great",
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "my-package",
					Version:  "0.0.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/files.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with aliases",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-aliases.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@babel/helper-validator-identifier",
					Version:  "7.22.20",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-aliases.v2.lock", 22),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "ansi-regex",
					Version:  "6.0.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-aliases.v2.lock", 15),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "ansi-regex",
					Version:  "5.0.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/with-aliases.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "exclude root",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/exclude-root.v2.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@ws/ansi-regex",
					Version:  "0.0.0-use.local",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/exclude-root.v2.lock", 8),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:     "ansi-regex",
					Version:  "6.1.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/exclude-root.v2.lock", 16),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := yarnlock.Extractor{}

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

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

package cargolock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graphtest"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/cargolock"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "Empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "Cargo.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.Cargo.lock",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := cargolock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cargolock.New: %v", err)
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
			Name: "Invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "addr2line",
					Version:  "0.15.2",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/one-package.lock", 6),
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "addr2line",
					Version:  "0.15.2",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.lock", 6),
				},
				{
					Name:     "syn",
					Version:  "1.0.73",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.lock", 15),
				},
			},
		},
		{
			Name: "two packages with local",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages-with-local.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "addr2line",
					Version:  "0.15.2",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages-with-local.lock", 6),
				},
				{
					Name:     "local-rust-pkg",
					Version:  "0.1.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages-with-local.lock", 15),
				},
			},
		},
		{
			Name: "package with build string",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/package-with-build-string.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "wasi",
					Version:  "0.10.2+wasi-snapshot-preview1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/package-with-build-string.lock", 6),
				},
			},
		},
		// We can disambiguate duplicate packages because cargolock defines packages
		// in sequential blocks.
		{
			Name: "duplicate packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/duplicate.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "syn",
					Version:  "1.0.73",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/duplicate.lock", 6),
				},
				{
					Name:     "syn",
					Version:  "2.0.0",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/duplicate.lock", 12),
				},
			},
		},
		{
			Name: "package with comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/package-with-comments.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "addr2line",
					Version:  "0.15.2",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/package-with-comments.lock", 6),
				},
				{
					Name:     "syn",
					Version:  "1.0.73",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/package-with-comments.lock", 13),
				},
			},
		},
		{
			Name: "many packages in appearance order",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/many-packages.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "zstd",
					Version:  "0.11.2",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/many-packages.lock", 6),
				},
				{
					Name:     "aho-corasick",
					Version:  "0.7.18",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/many-packages.lock", 12),
				},
				{
					Name:     "memchr",
					Version:  "2.4.1",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/many-packages.lock", 21),
				},
				{
					Name:     "syn",
					Version:  "1.0.109",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/many-packages.lock", 27),
				},
				{
					Name:     "libc",
					Version:  "0.2.140",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/many-packages.lock", 33),
				},
				{
					Name:     "syn",
					Version:  "2.0.15",
					PURLType: purl.TypeCargo,
					Location: extractor.LocationFromPathAndLine("testdata/many-packages.lock", 39),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := cargolock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cargolock.New: %v", err)
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

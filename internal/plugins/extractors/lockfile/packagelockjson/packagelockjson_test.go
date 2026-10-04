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

package packagelockjson_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graphtest"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/units"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:         "Empty path",
			path:         filepath.FromSlash(""),
			wantRequired: false,
		},
		{
			name:             "package-lock.json",
			path:             filepath.FromSlash("package-lock.json"),
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package-lock.json at the end of a path",
			path:             filepath.FromSlash("path/to/my/package-lock.json"),
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "package-lock.json as path segment",
			path:         filepath.FromSlash("path/to/my/package-lock.json/file"),
			wantRequired: false,
		},
		{
			name:         "package-lock.json.file (wrong extension)",
			path:         filepath.FromSlash("path/to/my/package-lock.json.file"),
			wantRequired: false,
		},
		{
			name:         "path.to.my.package.lock.json",
			path:         filepath.FromSlash("path.to.my.package.lock.json"),
			wantRequired: false,
		},
		{
			name:         "skip from inside node_modules dir",
			path:         filepath.FromSlash("foo/node_modules/bar/package-lock.json"),
			wantRequired: false,
		},
		{
			name:             "package-lock.json required if file size < max file size",
			path:             "foo/package-lock.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package-lock.json required if file size == max file size",
			path:             "foo/package-lock.json",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package-lock.json not required if file size > max file size",
			path:             "foo/package-lock.json",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "package-lock.json required if max file size set to 0",
			path:             "foo/package-lock.json",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "npm-shrinkwrap.json",
			path:             filepath.FromSlash("npm-shrinkwrap.json"),
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "npm-shrinkwrap.json at the end of a path",
			path:             filepath.FromSlash("path/to/my/npm-shrinkwrap.json"),
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "npm-shrinkwrap.json as path segment",
			path:         filepath.FromSlash("path/to/my/npm-shrinkwrap.json/file"),
			wantRequired: false,
		},
		{
			name:         "npm-shrinkwrap.json.file (wrong extension)",
			path:         filepath.FromSlash("path/to/my/npm-shrinkwrap.json.file"),
			wantRequired: false,
		},
		{
			name:         "path.to.my.npm-shrinkwrap.json",
			path:         filepath.FromSlash("path.to.my.npm-shrinkwrap.json"),
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := packagelockjson.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("packagelockjson.New: %v", err)
			}
			e.(*packagelockjson.Extractor).Stats = collector

			// Set default size if not provided.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestMetricCollector(t *testing.T) {
	tests := []struct {
		name             string
		inputConfig      extracttest.ScanInputMockConfig
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "invalid_package-lock.json",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "valid_package-lock.json",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v1.json",
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			extr, err := packagelockjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packagelockjson.New: %v", err)
			}
			extr.(*packagelockjson.Extractor).Stats = collector

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			// Results are tested in the other files
			_, _ = extr.Extract(t.Context(), &scanInput)

			gotResultMetric := collector.FileExtractedResult(tt.inputConfig.Path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.inputConfig.Path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.inputConfig.Path)
			if gotFileSizeMetric != scanInput.Info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.inputConfig.Path, gotFileSizeMetric, scanInput.Info.Size())
			}
		})
	}
}

func TestExtractor_Extract_Shrinkwrap_JSON(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "null json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/null.v2.jsontest",
			},
			WantErr: extracttest.ContainsErrStr{Str: "decoded null JSON value"},
		},
		{
			Name: "valid package-lock.json only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/package-lock-only/package-lock.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "wrappy",
					Version:  "1.0.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/package-lock-only/package-lock.json", 13),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "supports-color",
					Version:  "5.5.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/package-lock-only/package-lock.json", 18),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "valid npm-shrinkwrap.json only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/npm-shrinkwrap-only/npm-shrinkwrap.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "wrappy",
					Version:  "1.0.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/npm-shrinkwrap-only/npm-shrinkwrap.json", 13),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "supports-color",
					Version:  "5.5.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/npm-shrinkwrap-only/npm-shrinkwrap.json", 18),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "valid package-lock.json and npm-shrinkwrap.json and extract package-lock.json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/both/package-lock.json",
			},
			WantPackages: nil,
		},
		{
			Name: "valid package-lock.json and npm-shrinkwrap.json and extract npm-shrinkwrap.json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/both/npm-shrinkwrap.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "wrappy",
					Version:  "1.0.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/both/npm-shrinkwrap.json", 13),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "supports-color",
					Version:  "5.5.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPathAndLine("testdata/both/npm-shrinkwrap.json", 18),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			extr, err := packagelockjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packagelockjson.New: %v", err)
			}
			extr.(*packagelockjson.Extractor).Stats = collector

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

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.InputConfig.Path)
			if gotFileSizeMetric != scanInput.Info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.InputConfig.Path, gotFileSizeMetric, scanInput.Info.Size())
			}
		})
	}
}

func TestExtractor_Extract_V1_LineNumbers(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "nested dependencies v1 line numbers",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "postcss",
					Version:    "6.0.23",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/nested-dependencies.v1.json", 5),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-calc",
					Version:    "7.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/nested-dependencies.v1.json", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss",
					Version:    "7.0.16",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/nested-dependencies.v1.json", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "6.1.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/nested-dependencies.v1.json", 36),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPathAndLine("testdata/nested-dependencies.v1.json", 46),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			extr, err := packagelockjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packagelockjson.New: %v", err)
			}
			extr.(*packagelockjson.Extractor).Stats = collector

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

func TestDeterminePackageSource(t *testing.T) {
	tests := []struct {
		name     string
		resolved string
		commit   string
		want     metadata.NPMPackageSource
	}{
		{
			name:     "official npm registry https",
			resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "official npm registry http",
			resolved: "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "npmmirror registry",
			resolved: "https://registry.npmmirror.com/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "tencent npm mirror",
			resolved: "https://mirrors.cloud.tencent.com/npm/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "huawei npm mirror",
			resolved: "https://repo.huaweicloud.com/repository/npm/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "tsinghua npm mirror",
			resolved: "https://mirrors.tuna.tsinghua.edu.cn/npm/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "custom repo containing npm in domain or path",
			resolved: "https://my-internal-npm-repo.corp/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.PublicRegistry,
		},
		{
			name:     "non-npm http tarball",
			resolved: "https://artifactory.corp.internal/artifactory/repo/lodash/-/lodash-4.17.21.tgz",
			want:     metadata.Other,
		},
		{
			name:     "github archive tarball without commit",
			resolved: "https://codeload.github.com/foo/bar/tar.gz/v1.0.0",
			want:     metadata.Other,
		},
		{
			name:     "git+ssh dependency",
			resolved: "git+ssh://git@github.com/foo/bar.git",
			want:     metadata.Other,
		},
		{
			name:     "git+https dependency",
			resolved: "git+https://github.com/foo/bar.git",
			want:     metadata.Other,
		},
		{
			name:     "git+https dependency even if containing npm",
			resolved: "git+https://github.com/npm/cli.git",
			want:     metadata.Other,
		},
		{
			name:     "git protocol dependency",
			resolved: "git://github.com/foo/bar.git",
			want:     metadata.Other,
		},
		{
			name:     "ssh protocol dependency",
			resolved: "ssh://git@github.com/foo/bar.git",
			want:     metadata.Other,
		},
		{
			name:     "github shorthand dependency",
			resolved: "github:npm/cli#af885e2e890b9ef0875edd2b117305119ee5bdc5",
			want:     metadata.Other,
		},
		{
			name:     "git dependency with commit hash",
			resolved: "git+ssh://git@github.com/foo/bar.git",
			commit:   "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
			want:     metadata.Other,
		},
		{
			name:     "commit hash with empty resolved",
			resolved: "",
			commit:   "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			want:     metadata.Other,
		},
		{
			name:     "local file protocol",
			resolved: "file:../my-pkg",
			want:     metadata.Local,
		},
		{
			name:     "local relative path",
			resolved: "packages/auth",
			want:     metadata.Local,
		},
		{
			name:     "empty resolved",
			resolved: "",
			want:     metadata.Local,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packagelockjson.DeterminePackageSource(tt.resolved, tt.commit)
			if got != tt.want {
				t.Errorf("DeterminePackageSource(%q, %q) = %v, want %v", tt.resolved, tt.commit, got, tt.want)
			}
		})
	}
}

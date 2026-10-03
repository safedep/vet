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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/testcollector"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graphtest"
)

func TestNPMLockExtractor_Extract_V1(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.v1.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/one-package.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/one-package-dev.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/two-packages.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/two-packages.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/scoped-packages.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/code-frame",
					Version:    "7.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/scoped-packages.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "postcss",
					Version:    "6.0.23",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies dup",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies-dup.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "supports-color",
					Version:    "2.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-display-values",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-timing-functions",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-string",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-whitespace",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "cssnano-preset-default",
					Version:    "4.0.7",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-merge-longhand",
					Version:    "4.0.11",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-overridden",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-reduce-transforms",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-svgo",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-ordered-values",
					Version:    "4.1.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-selectors",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "babel-code-frame",
					Version:    "6.26.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "css-declaration-sorter",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-url",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-params",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-colormin",
					Version:    "4.0.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "autoprefixer",
					Version:    "9.5.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-charset",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-unique-selectors",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-reduce-initial",
					Version:    "4.0.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-positions",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-duplicates",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-loader",
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "cssnano",
					Version:    "4.1.10",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-empty",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-repeat-style",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-convert-values",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "friendly-errors-webpack-plugin",
					Version:    "1.7.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@vue/component-compiler-utils",
					Version:    "2.6.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-merge-rules",
					Version:    "4.0.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-unicode",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-font-values",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-gradients",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "cssnano-util-raw-cache",
					Version:    "4.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
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
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-comments",
					Version:    "4.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/nested-dependencies-dup.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/commits.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@segment/analytics.js-integration-facebook-pixel",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
						Repo:   "https://github.com/segmentio/analytics.js-integrations",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ansi-styles",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "babel-preset-php",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
						Repo:   "https://gitlab.com/kornelski/babel-preset-php",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number-1",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "is-number-1",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "be5935f8d2595bcd97b05718ef1eeae08d812e10",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "is-number-2",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number-2",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "82dcc8e914dabd9305ab9ae580709a7825e824f5",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "is-number-3",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "is-number-3",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "is-number-4",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "is-number-5",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "is-number-6",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
						Repo:   "https://github.com/jonschlinkert/is-number",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:       "postcss-calc",
					Version:    "7.0.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "raven-js",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
						Repo:   "https://github.com/getsentry/raven-js",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "slick-carousel",
					Version:  "",
					PURLType: purl.TypeGit,
					Location: extractor.LocationFromPath("testdata/commits.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "280b560161b751ba226d50c7db1e0a14a78c2de0",
						Repo:   "https://github.com/brianfryer/slick",
					},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Other,
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "lodash",
					Version:    "1.3.1",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/files.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "other_package",
					Version:    "",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/files.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Local,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "alias",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/alias.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "@babel/code-frame",
					Version:    "7.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/alias.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "string-width",
					Version:    "4.2.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/alias.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "string-width",
					Version:    "5.1.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/alias.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-package.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/optional-package.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{"dev", "optional"},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/optional-package.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.PublicRegistry,
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "same package different groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/same-package-different-groups.v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "eslint",
					Version:    "1.2.3",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/same-package-different-groups.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Local,
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:       "table",
					Version:    "1.0.0",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/same-package-different-groups.v1.json"),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &metadata.JavascriptPackageMetadata{
						Source:       metadata.Local,
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ajv",
					Version:    "5.5.2",
					PURLType:   purl.TypeNPM,
					Location:   extractor.LocationFromPath("testdata/same-package-different-groups.v1.json"),
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
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess), graphtest.IgnoreGraph, cmpopts.IgnoreFields(location.File{}, "LineNumber")); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.InputConfig.Path)
			if gotFileSizeMetric != scanInput.Info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.InputConfig.Path, gotFileSizeMetric, scanInput.Info.Size())
			}
		})
	}
}

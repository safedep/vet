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

package githubactions_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	"github.com/safedep/vet/v2/internal/plugins/extractors/githubactions"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "workflow_file_yml_at_repo_root",
			path: ".github/workflows/ci.yml",
			want: true,
		},
		{
			name: "workflow_file_yaml_at_repo_root",
			path: ".github/workflows/release.yaml",
			want: true,
		},
		{
			name: "workflow_file_inside_subdirectory_repo",
			path: "src/myrepo/.github/workflows/build.yml",
			want: true,
		},
		{
			name: "absolute_style_path_with_workflows",
			path: "home/user/proj/.github/workflows/test.yml",
			want: true,
		},
		{
			name: "yml_under_workflows_subdir_should_not_match",
			path: ".github/workflows/sub/build.yml",
			want: false,
		},
		{
			name: "yml_under_dot_github_but_not_workflows",
			path: ".github/dependabot.yml",
			want: false,
		},
		{
			name: "yml_under_workflows_but_not_dot_github",
			path: "workflows/build.yml",
			want: false,
		},
		{
			name: "non_yaml_extension_under_workflows",
			path: ".github/workflows/notes.txt",
			want: false,
		},
		{
			name: "markdown_file_under_workflows",
			path: ".github/workflows/README.md",
			want: false,
		},
		{
			name: "unrelated_yaml_file",
			path: "config/app.yml",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := githubactions.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("githubactions.New() error: %v", err)
			}
			fi := fakefs.FakeFileInfo{FileName: tc.path, FileSize: 1024}
			got := extr.FileRequired(simplefileapi.New(tc.path, fi))
			if got != tc.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestFileRequired_FileSizeLimit(t *testing.T) {
	extr, err := githubactions.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
	if err != nil {
		t.Fatalf("githubactions.New() error: %v", err)
	}
	path := ".github/workflows/big.yml"
	fi := fakefs.FakeFileInfo{FileName: path, FileSize: 200}
	if extr.FileRequired(simplefileapi.New(path, fi)) {
		t.Errorf("FileRequired(%q) = true, want false (over size limit)", path)
	}
}

func loc(path string, line int) extractor.PackageLocation {
	return extractor.PackageLocation{
		Descriptor: &location.Location{
			File: &location.File{
				Path:       path,
				LineNumber: line,
			},
		},
	}
}

func sourceCode(repo, commit string) *extractor.SourceCodeIdentifier {
	return &extractor.SourceCodeIdentifier{Repo: repo, Commit: commit}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
	}{
		{
			name: "valid_workflow_with_steps_and_reusable_workflows",
			path: "testdata/valid.yml",
			wantPackages: []*extractor.Package{
				{
					Name:       "actions/checkout",
					Version:    "v4",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/valid.yml", 11),
					SourceCode: sourceCode("https://github.com/actions/checkout", ""),
				},
				{
					Name:     "actions/setup-node",
					Version:  "8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
					PURLType: purl.TypeGithub,
					Location: loc("testdata/valid.yml", 12),
					SourceCode: sourceCode(
						"https://github.com/actions/setup-node",
						"8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
					),
				},
				{
					Name:       "actions/setup-python",
					Version:    "v5.0.0",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/valid.yml", 13),
					SourceCode: sourceCode("https://github.com/actions/setup-python", ""),
				},
				{
					Name:       "docker/build-push-action",
					Version:    "v6",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/valid.yml", 16),
					SourceCode: sourceCode("https://github.com/docker/build-push-action", ""),
				},
				{
					Name:       "octo-org/example-repo",
					Version:    "v1.2.3",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/valid.yml", 21),
					SourceCode: sourceCode("https://github.com/octo-org/example-repo", ""),
				},
				{
					Name:     "octo-org/example-repo",
					Version:  "1234567890abcdef1234567890abcdef12345678",
					PURLType: purl.TypeGithub,
					Location: loc("testdata/valid.yml", 24),
					SourceCode: sourceCode(
						"https://github.com/octo-org/example-repo",
						"1234567890abcdef1234567890abcdef12345678",
					),
				},
			},
		},
		{
			name: "edge_cases_skip_local_docker_and_malformed",
			path: "testdata/edge_cases.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:       "actions/checkout",
					Version:    "v4",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/edge_cases.yaml", 12),
					SourceCode: sourceCode("https://github.com/actions/checkout", ""),
				},
				{
					Name:       "github/codeql-action",
					Version:    "v3",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/edge_cases.yaml", 17),
					SourceCode: sourceCode("https://github.com/github/codeql-action", ""),
				},
				{
					Name:       "github/codeql-action",
					Version:    "v3",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/edge_cases.yaml", 18),
					SourceCode: sourceCode("https://github.com/github/codeql-action", ""),
				},
				{
					Name:       "actions/cache",
					Version:    "main",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/edge_cases.yaml", 23),
					SourceCode: sourceCode("https://github.com/actions/cache", ""),
				},
				{
					Name:       "actions/upload-artifact",
					Version:    "v4",
					PURLType:   purl.TypeGithub,
					Location:   loc("testdata/edge_cases.yaml", 24),
					SourceCode: sourceCode("https://github.com/actions/upload-artifact", ""),
				},
			},
		},
		{
			name:         "no_jobs_section",
			path:         "testdata/no_jobs.yml",
			wantPackages: nil,
		},
		{
			name:         "empty_file",
			path:         "testdata/empty.yml",
			wantPackages: nil,
		},
		{
			name:         "invalid_yaml_no_packages_no_error",
			path:         "testdata/invalid.yml",
			wantPackages: nil,
		},
		{
			name:         "jobs_field_is_a_list_not_a_map",
			path:         "testdata/jobs_not_map.yml",
			wantPackages: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := githubactions.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("githubactions.New() error: %v", err)
			}
			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{Path: tc.path})
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(t.Context(), &input)
			if err != nil {
				t.Fatalf("%s.Extract(%q) unexpected error: %v", extr.Name(), tc.path, err)
			}
			wantInv := inventory.Inventory{Packages: tc.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tc.path, diff)
			}
		})
	}
}

func TestExtract_PURLAndEcosystem(t *testing.T) {
	extr, err := githubactions.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("githubactions.New() error: %v", err)
	}
	input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/valid.yml",
	})
	defer extracttest.CloseTestScanInput(t, input)

	inv, err := extr.Extract(t.Context(), &input)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(inv.Packages) == 0 {
		t.Fatalf("Extract returned no packages")
	}
	pkg := inv.Packages[0]
	gotPURL := pkg.PURL().String()
	wantPURL := "pkg:github/actions/checkout@v4"
	if gotPURL != wantPURL {
		t.Errorf("PURL = %q, want %q", gotPURL, wantPURL)
	}
	gotEco := pkg.Ecosystem().String()
	wantEco := "GitHub Actions"
	if gotEco != wantEco {
		t.Errorf("Ecosystem = %q, want %q", gotEco, wantEco)
	}
}

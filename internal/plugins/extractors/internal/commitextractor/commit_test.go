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

package commitextractor_test

import (
	"testing"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/commitextractor"
)

func TestTryExtractCommit(t *testing.T) {
	tests := []struct {
		name       string
		resolution string
		wantCommit string
	}{
		{
			name:       "git+ssh with hash",
			resolution: "git+ssh://git@github.com:G-Rath/npm-git-repo-2#0a2d2506c1fe299691fc5db53a2097db3bd615bc",
			wantCommit: "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
		},
		{
			name:       "codeload tarball",
			resolution: "https://codeload.github.com/G-Rath/npm-git-repo-2/tar.gz/0a2d2506c1fe299691fc5db53a2097db3bd615bc",
			wantCommit: "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
		},
		{
			name:       "git+https with commit",
			resolution: "git+https://git@github.com/my-org/my-package.git#b3bd3f1b3dad036e671251f5258beaae398f983a",
			wantCommit: "b3bd3f1b3dad036e671251f5258beaae398f983a",
		},
		{
			name:       "github commit prefix",
			resolution: "https://github.com/typegoose/typegoose.git#commit:3ed06e5097ab929f69755676fee419318aaec73a",
			wantCommit: "3ed06e5097ab929f69755676fee419318aaec73a",
		},
		{
			name:       "github shorthand",
			resolution: "github:prettier/prettier-synchronized#527e8ce",
			wantCommit: "527e8ce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commitextractor.TryExtractCommit(tt.resolution)
			if got != tt.wantCommit {
				t.Errorf("TryExtractCommit(%q) = %q, want %q", tt.resolution, got, tt.wantCommit)
			}
		})
	}
}

func TestTryExtractRepo(t *testing.T) {
	tests := []struct {
		name       string
		resolution string
		wantRepo   string
	}{
		{
			name:       "git+ssh scp syntax",
			resolution: "git+ssh://git@github.com:G-Rath/npm-git-repo-2#0a2d2506c1fe299691fc5db53a2097db3bd615bc",
			wantRepo:   "https://github.com/G-Rath/npm-git-repo-2",
		},
		{
			name:       "codeload tarball",
			resolution: "https://codeload.github.com/G-Rath/npm-git-repo-2/tar.gz/0a2d2506c1fe299691fc5db53a2097db3bd615bc",
			wantRepo:   "https://github.com/G-Rath/npm-git-repo-2",
		},
		{
			name:       "git+https with git user",
			resolution: "git+https://git@github.com/my-org/my-package.git#b3bd3f1b3dad036e671251f5258beaae398f983a",
			wantRepo:   "https://github.com/my-org/my-package",
		},
		{
			name:       "git protocol",
			resolution: "git://github.com/angular/bower-angular-animate.git#e7f778fc054a086ba3326d898a00fa1bc78650a8",
			wantRepo:   "https://github.com/angular/bower-angular-animate",
		},
		{
			name:       "ssh protocol",
			resolution: "ssh://github.com/substack/minimist.git#3754568bfd43a841d2d72d7fb54598635aea8fa4",
			wantRepo:   "https://github.com/substack/minimist",
		},
		{
			name:       "https with hash",
			resolution: "https://github.com/bats-core/bats-assert#4bdd58d3fbcdce3209033d44d884e87add1d8405",
			wantRepo:   "https://github.com/bats-core/bats-assert",
		},
		{
			name:       "yarn v2 package prefix",
			resolution: "@typegoose/typegoose@https://github.com/typegoose/typegoose.git#commit:3ed06e5097ab929f69755676fee419318aaec73a",
			wantRepo:   "https://github.com/typegoose/typegoose",
		},
		{
			name:       "github shorthand",
			resolution: "github:prettier/prettier-synchronized#527e8ce",
			wantRepo:   "https://github.com/prettier/prettier-synchronized",
		},
		{
			name:       "gitlab shorthand with git+ssh prefix",
			resolution: "git+ssh://gitlab:kornelski/babel-preset-php#1ae6dc1267500360b411ec711b8aeac8c68b2246",
			wantRepo:   "https://gitlab.com/kornelski/babel-preset-php",
		},
		{
			name:       "bitbucket scp syntax",
			resolution: "git@bitbucket.org:my-org/my-bitbucket-project.git",
			wantRepo:   "https://bitbucket.org/my-org/my-bitbucket-project",
		},
		{
			name:       "ssh with scp syntax and commit",
			resolution: "ssh://git@github.com:my-org/is-really-great.git#commit=191eeef50c584714e1fb8927d17ee72b3b8c97c4",
			wantRepo:   "https://github.com/my-org/is-really-great",
		},
		{
			name:       "git+ssh with path slash",
			resolution: "git+ssh://git@bitbucket.org/casasoftag/casadistance.git#f0308391f0c50104182bfb2332a53e4e523a4603",
			wantRepo:   "https://bitbucket.org/casasoftag/casadistance",
		},
		{
			name:       "yarn v2 git scheme prefix",
			resolution: "my-package@git://github.com/my-org/my-package.git#v1.0.0",
			wantRepo:   "https://github.com/my-org/my-package",
		},
		{
			name:       "yarn v2 git+https scheme prefix",
			resolution: "@scope/pkg@git+https://github.com/my-org/my-package.git#b3bd3f1b3dad036e671251f5258beaae398f983a",
			wantRepo:   "https://github.com/my-org/my-package",
		},
		{
			name:       "empty host returns empty",
			resolution: "https:///only-path",
			wantRepo:   "",
		},
		{
			name:       "empty path returns empty",
			resolution: "https://github.com",
			wantRepo:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commitextractor.TryExtractRepo(tt.resolution)
			if got != tt.wantRepo {
				t.Errorf("TryExtractRepo(%q) = %q, want %q", tt.resolution, got, tt.wantRepo)
			}
		})
	}
}

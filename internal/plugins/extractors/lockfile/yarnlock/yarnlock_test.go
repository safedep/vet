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

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/yarnlock"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			inputPath: "",
			want:      false,
		},
		{
			inputPath: "yarn.lock",
			want:      true,
		},
		{
			inputPath: "path/to/my/yarn.lock",
			want:      true,
		},
		{
			inputPath: "path/to/my/yarn.lock/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/yarn.lock.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.yarn.lock",
			want:      false,
		},
		{
			inputPath: "foo/node_modules/bar/yarn.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := yarnlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("yarnlock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

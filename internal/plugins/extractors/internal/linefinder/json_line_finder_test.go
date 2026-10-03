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

package linefinder

import (
	"testing"
)

func TestJSONLineFinder(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		path     string
		wantLine int
	}{
		{
			name:     "simple flat json",
			json:     "{\n  \"foo\": \"bar\",\n  \"baz\": 123\n}",
			path:     "baz",
			wantLine: 3,
		},
		{
			name: "nested json",
			json: `{
  "foo": {
    "bar": "baz",
    "qux": [
      1,
      2
    ]
  }
}`,
			path:     "foo.qux",
			wantLine: 4,
		},
		{
			name: "escaped key",
			json: `{
  "foo.bar": "baz"
}`,
			path:     "foo\\.bar",
			wantLine: 2,
		},
		{
			name:     "non-existent path",
			json:     "{\n  \"foo\": \"bar\"\n}",
			path:     "invalid",
			wantLine: 0,
		},
		{
			name:     "value at line start",
			json:     "{\n\"baz\":\n123\n}",
			path:     "baz",
			wantLine: 3,
		},
		{
			name:     "value on last line",
			json:     "{\"baz\":\n123}",
			path:     "baz",
			wantLine: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			finder := NewJSONLineFinder([]byte(tc.json))
			got := finder.LineOf(tc.path)
			if got != tc.wantLine {
				t.Errorf("LineOf(%q) = %d, want %d", tc.path, got, tc.wantLine)
			}
		})
	}
}

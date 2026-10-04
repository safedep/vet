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

import "testing"

func TestOffsetFinder(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		offset   int
		wantLine int
	}{
		{
			name:     "first line",
			content:  "foo\nbar\nbaz\n",
			offset:   1,
			wantLine: 1,
		},
		{
			name:     "second line",
			content:  "foo\nbar\nbaz\n",
			offset:   5,
			wantLine: 2,
		},
		{
			name:     "exact newline",
			content:  "foo\nbar\nbaz\n",
			offset:   3,
			wantLine: 1,
		},
		{
			name:     "last line without newline",
			content:  "foo\nbar",
			offset:   6,
			wantLine: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			finder := NewOffsetFinder([]byte(tc.content))
			if got := finder.LineOfOffset(tc.offset); got != tc.wantLine {
				t.Errorf("LineOfOffset(%d) = %d, want %d", tc.offset, got, tc.wantLine)
			}
		})
	}
}

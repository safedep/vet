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

import "sort"

// OffsetFinder finds line numbers from raw byte offsets.
type OffsetFinder struct {
	lineOffsets []int
}

// NewOffsetFinder creates a new OffsetFinder.
func NewOffsetFinder(content []byte) *OffsetFinder {
	lineOffsets := []int{0}
	for i, b := range content {
		if b == '\n' {
			lineOffsets = append(lineOffsets, i+1)
		}
	}
	return &OffsetFinder{lineOffsets: lineOffsets}
}

// LineOfOffset returns the 1-based line number for the given byte offset.
func (f *OffsetFinder) LineOfOffset(offset int) int {
	return sort.Search(len(f.lineOffsets), func(i int) bool {
		return f.lineOffsets[i] > offset
	})
}

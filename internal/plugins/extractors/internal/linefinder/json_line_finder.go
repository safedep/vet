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

// Package linefinder provides utility functions for finding package line numbers in manifest files.
package linefinder

import (
	"github.com/tidwall/gjson"
)

// JSONLineFinder finds line numbers of JSON paths.
type JSONLineFinder struct {
	// json is the raw JSON bytes being analyzed.
	json []byte
	// offsetFinder delegates the binary search.
	offsetFinder *OffsetFinder
}

// NewJSONLineFinder creates a new JSONLineFinder.
func NewJSONLineFinder(json []byte) *JSONLineFinder {
	return &JSONLineFinder{
		json:         json,
		offsetFinder: NewOffsetFinder(json),
	}
}

// LineOf returns the line number of the given JSON path.
// If the path is not found or cannot be parsed, it returns 0.
func (f *JSONLineFinder) LineOf(path string) int {
	// Verify the path exists in the JSON.
	res := gjson.GetBytes(f.json, path)
	if !res.Exists() {
		return 0
	}
	// Binary search for the line.
	// `res.Index` is the raw byte offset, NOT the line number, so we need to do
	// a binary search on the line offsets and return the index of the matching offset.
	return f.offsetFinder.LineOfOffset(res.Index)
}

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

// Package units provides constants for common units.
package units

const (
	// KiB is a Kibibyte
	KiB = int64(1024)
	// MiB is a Mebibyte
	MiB = 1024 * KiB
	// GiB is a Gibibyte
	GiB = 1024 * MiB
	// TiB is a Tebibyte
	TiB = 1024 * GiB
	// PiB is a Pebibyte
	PiB = 1024 * TiB
	// EiB is a Exbibyte
	EiB = 1024 * PiB
)

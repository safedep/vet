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

// Package packagelockjson provides the structures for npm's package-lock.json lockfile format.
package npmlock

// LockFile is the npm package-lock.json lockfile.
type LockFile struct {
	Version int `json:"lockfileVersion"`
	// npm v1- lockfiles use "dependencies"
	Dependencies map[string]Dependency `json:"dependencies,omitempty"`
	// npm v2+ lockfiles use "packages"
	Packages map[string]Package `json:"packages,omitempty"`
}

// Dependency is the representation of an installed dependency in lockfileVersion 1
type Dependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires     map[string]string     `json:"requires,omitempty"`
	Dependencies map[string]Dependency `json:"dependencies,omitempty"`
}

// DepGroups returns the list of groups this dependency belongs to.
// May be empty, or one or both of "dev", "optional".
func (dep Dependency) DepGroups() []string {
	if dep.Dev && dep.Optional {
		return []string{"dev", "optional"}
	}
	if dep.Dev {
		return []string{"dev"}
	}
	if dep.Optional {
		return []string{"optional"}
	}

	return nil
}

// Package is the representation of an installed dependency in lockfileVersion 2+
type Package struct {
	// For an aliased package, Name is the real package name
	Name      string `json:"name,omitempty"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity,omitempty"`
	Link      bool   `json:"link,omitempty"`

	Dev         bool `json:"dev,omitempty"`
	DevOptional bool `json:"devOptional,omitempty"`
	Optional    bool `json:"optional,omitempty"`
	InBundle    bool `json:"inBundle,omitempty"`

	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	PeerDependenciesMeta map[string]struct {
		Optional bool `json:"optional,omitempty"`
	} `json:"peerDependenciesMeta,omitempty"`
}

// DepGroups returns the list of groups this package belongs to.
// Supported groups are "bundled", "dev", and "optional", with an
// empty group implying a production dependency.
func (pkg Package) DepGroups() []string {
	var groups []string

	if pkg.InBundle {
		groups = []string{"bundled"}
	}

	if pkg.DevOptional {
		groups = append(groups, "dev", "optional")

		return groups
	}

	if pkg.Dev {
		groups = append(groups, "dev")
	}
	if pkg.Optional {
		groups = append(groups, "optional")
	}

	return groups
}

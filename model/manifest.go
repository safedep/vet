package model

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
)

// ManifestKind names what a manifest file is.
type ManifestKind string

const (
	ManifestKindLockfile ManifestKind = "lockfile"
	ManifestKindManifest ManifestKind = "manifest"
	ManifestKindWorkflow ManifestKind = "workflow"
	ManifestKindSBOM     ManifestKind = "sbom"
	ManifestKindImage    ManifestKind = "image"
	ManifestKindPURL     ManifestKind = "purl"
	ManifestKindEndpoint ManifestKind = "endpoint"
	// ManifestKindAgentConfig is an agent or editor config file. It holds
	// no package. The agentconfig control reads the file.
	ManifestKindAgentConfig ManifestKind = "agent-config"
	// ManifestKindFile is one file that the hidden-code controls read as a
	// whole, such as a build config or a font file. It holds no package.
	// vet adds it only for a file that shows a sign of hidden code.
	ManifestKindFile ManifestKind = "file"
	// ManifestKindInstalled is the metadata of a package on disk, such as
	// node_modules/left-pad/package.json, or a binary that records its
	// modules.
	ManifestKindInstalled ManifestKind = "installed"
)

// Origin returns where the packages of a manifest of this kind come from.
// The packages of an installed manifest and of the endpoint are on disk.
// Every other manifest declares its packages.
func (k ManifestKind) Origin() Packages {
	if k == ManifestKindInstalled || k == ManifestKindEndpoint {
		return PackagesInstalled
	}
	return PackagesDeclared
}

// Packages selects where a scan finds packages.
type Packages string

const (
	// PackagesDeclared reads the lockfiles and the manifests.
	PackagesDeclared Packages = "declared"
	// PackagesInstalled reads the packages on disk.
	PackagesInstalled Packages = "installed"
	// PackagesAll reads both.
	PackagesAll Packages = "all"
)

// PackagesValues are the values of Packages, in the order of the docs.
var PackagesValues = []Packages{PackagesDeclared, PackagesInstalled, PackagesAll}

// Declared reports that p reads the lockfiles and the manifests.
func (p Packages) Declared() bool { return p == PackagesDeclared || p == PackagesAll }

// Installed reports that p reads the packages on disk.
func (p Packages) Installed() bool { return p == PackagesInstalled || p == PackagesAll }

// Manifest is one file or input that declares packages.
type Manifest struct {
	// ID is stable for the same path in the same target.
	ID        string       `json:"id"`
	Path      string       `json:"path"`
	Ecosystem Ecosystem    `json:"ecosystem,omitempty"`
	Kind      ManifestKind `json:"kind"`
	Change    Change       `json:"change,omitempty"`
	// LockfileOnly reports, in pull request mode, a change to a lockfile
	// that leaves the manifest file next to it, such as package.json, as it
	// was.
	LockfileOnly bool `json:"lockfile_only,omitempty"`

	// Extractor is the name of the extractor that read the manifest.
	Extractor string `json:"extractor,omitempty"`

	// Packages is the flat set of packages. It is always set.
	Packages []*Package `json:"-"`

	// Graph is the dependency graph, or nil when the extractor has no edges.
	Graph *Graph `json:"-"`

	// Root is the file system of the target, for controls that read the
	// manifest file. It is nil when the manifest has no file.
	Root fs.FS `json:"-"`
}

// Package returns the package with the identity, or nil.
func (m *Manifest) Package(id PackageVersion) *Package {
	for _, p := range m.Packages {
		if p.ID.Equal(id) {
			return p
		}
	}
	return nil
}

// ReadFile reads the manifest file from the target root.
func (m *Manifest) ReadFile() ([]byte, error) {
	if m.Root == nil {
		return nil, fs.ErrNotExist
	}
	return fs.ReadFile(m.Root, m.Path)
}

// ManifestID returns the stable id of the manifest that an extractor reads
// from a path in a target: "m-" and 12 hex digits of the SHA-256 of the
// path and the extractor name. Two extractors can read one file.
func ManifestID(path, extractor string) string {
	sum := sha256.Sum256([]byte(path + "\x00" + extractor))
	return "m-" + hex.EncodeToString(sum[:6])
}

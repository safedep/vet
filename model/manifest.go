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
)

// Manifest is one file or input that declares packages.
type Manifest struct {
	// ID is stable for the same path in the same target.
	ID        string       `json:"id"`
	Path      string       `json:"path"`
	Ecosystem Ecosystem    `json:"ecosystem,omitempty"`
	Kind      ManifestKind `json:"kind"`
	Change    Change       `json:"change,omitempty"`

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
func (m *Manifest) Package(id PackageID) *Package {
	for _, p := range m.Packages {
		if p.ID == id {
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

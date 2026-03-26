package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPackageManifestFromContainerImage(t *testing.T) {
	cases := []struct {
		name              string
		imageRef          string
		location          string
		ecosystem         string
		expectedPath      string
		expectedNamespace string
		expectedType      ManifestSourceType
	}{
		{
			name:              "alpine apk manifest",
			imageRef:          "alpine:3.23",
			location:          "lib/apk/db/installed",
			ecosystem:         "Alpine:v3.23",
			expectedPath:      "lib/apk/db/installed",
			expectedNamespace: "alpine:3.23",
			expectedType:      ManifestSourceContainerImage,
		},
		{
			name:              "ubuntu deb manifest",
			imageRef:          "ubuntu:jammy",
			location:          "var/lib/dpkg/status",
			ecosystem:         "Debian",
			expectedPath:      "var/lib/dpkg/status",
			expectedNamespace: "ubuntu:jammy",
			expectedType:      ManifestSourceContainerImage,
		},
		{
			name:              "image with sha",
			imageRef:          "alpine:3.20@sha256:de4fe706",
			location:          "lib/apk/db/installed",
			ecosystem:         "Alpine:v3.20",
			expectedPath:      "lib/apk/db/installed",
			expectedNamespace: "alpine:3.20@sha256:de4fe706",
			expectedType:      ManifestSourceContainerImage,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := NewPackageManifestFromContainerImage(tc.imageRef, tc.location, tc.ecosystem)

			assert.NotNil(t, manifest)
			assert.Equal(t, tc.expectedType, manifest.Source.Type)
			assert.Equal(t, tc.expectedNamespace, manifest.Source.Namespace)
			assert.Equal(t, tc.expectedPath, manifest.Source.Path)
			assert.Equal(t, tc.ecosystem, manifest.Ecosystem)
		})
	}
}

func TestContainerImageManifestDisplayPath(t *testing.T) {
	manifest := NewPackageManifestFromContainerImage("alpine:3.23", "lib/apk/db/installed", "Alpine:v3.23")

	assert.Equal(t, "alpine:3.23:lib/apk/db/installed", manifest.Source.GetDisplayPath())
}

func TestContainerImageManifestUniqueIds(t *testing.T) {
	m1 := NewPackageManifestFromContainerImage("alpine:3.23", "lib/apk/db/installed", "Alpine:v3.23")
	m2 := NewPackageManifestFromContainerImage("ubuntu:jammy", "var/lib/dpkg/status", "Debian")

	assert.NotEqual(t, m1.Id(), m2.Id())
}

func TestContainerImageManifestAddPackages(t *testing.T) {
	manifest := NewPackageManifestFromContainerImage("alpine:3.23", "lib/apk/db/installed", "Alpine:v3.23")

	pkg1 := &Package{
		PackageDetails: NewPackageDetail("Alpine:v3.23", "musl", "1.2.5-r21"),
		Manifest:       manifest,
	}
	pkg2 := &Package{
		PackageDetails: NewPackageDetail("Alpine:v3.23", "busybox", "1.37.0-r30"),
		Manifest:       manifest,
	}

	manifest.AddPackage(pkg1)
	manifest.AddPackage(pkg2)

	assert.Equal(t, 2, len(manifest.GetPackages()))
	assert.Equal(t, "musl", manifest.GetPackages()[0].Name)
	assert.Equal(t, "busybox", manifest.GetPackages()[1].Name)

	// Both packages should reference the same manifest
	assert.Equal(t, manifest.Id(), pkg1.Manifest.Id())
	assert.Equal(t, manifest.Id(), pkg2.Manifest.Id())
}

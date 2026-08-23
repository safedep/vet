package models

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

func TestGetPackageUrl(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		pkgName   string
		version   string
		expected  string
	}{
		{
			name:      "alpine distro ecosystem uses apk type with distro qualifier",
			ecosystem: "Alpine:v3.20",
			pkgName:   "musl",
			version:   "1.2.5-r21",
			expected:  "pkg:apk/alpine/musl@1.2.5-r21?distro=v3.20",
		},
		{
			name:      "ubuntu distro ecosystem maps to deb with ubuntu namespace",
			ecosystem: "Ubuntu:22.04",
			pkgName:   "adduser",
			version:   "3.118ubuntu5",
			expected:  "pkg:deb/ubuntu/adduser@3.118ubuntu5?distro=22.04",
		},
		{
			name:      "red hat family normalizes to rhel rpm purl",
			ecosystem: "Red Hat Enterprise Linux:8",
			pkgName:   "curl",
			version:   "7.61.1-30.el8",
			expected:  "pkg:rpm/rhel/curl@7.61.1-30.el8?distro=8",
		},
		{
			name:      "unknown distro family keeps legacy rendering",
			ecosystem: "UnknownOS:1.0",
			pkgName:   "pkg-a",
			version:   "1.0",
			expected:  "pkg:unknownos:1.0/pkg-a@1.0",
		},
		{
			name:      "non distro ecosystems keep legacy rendering",
			ecosystem: "npm",
			pkgName:   "left-pad",
			version:   "1.3.0",
			expected:  "pkg:npm/left-pad@1.3.0",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &Package{PackageDetails: lockfile.PackageDetails{
				Ecosystem: lockfile.Ecosystem(c.ecosystem),
				Name:      c.pkgName,
				Version:   c.version,
			}}

			assert.Equal(t, c.expected, p.GetPackageUrl())
		})
	}
}

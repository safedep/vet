package scanner

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func TestCurrentVersionFromAvailableVersions(t *testing.T) {
	t.Run("prefers registry default version", func(t *testing.T) {
		versions := []*packagev1.PackageAvailableVersion{
			{Version: "v1.0.2"},
			{Version: "v6.0.0-rc.1"},
			{Version: "v5.2.2", DefaultVersion: true},
		}

		assert.Equal(t, "v5.2.2", currentVersionFromAvailableVersions(versions))
	})

	t.Run("falls back to highest semver version", func(t *testing.T) {
		versions := []*packagev1.PackageAvailableVersion{
			{Version: "v1.0.2"},
			{Version: "v5.2.2"},
			{Version: "v4.5.2"},
		}

		assert.Equal(t, "v5.2.2", currentVersionFromAvailableVersions(versions))
	})

	t.Run("skips empty versions", func(t *testing.T) {
		versions := []*packagev1.PackageAvailableVersion{
			{Version: ""},
			{Version: "v1.0.2"},
		}

		assert.Equal(t, "v1.0.2", currentVersionFromAvailableVersions(versions))
	})
}

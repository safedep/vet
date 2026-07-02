package scanner

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/models"
)

func TestBuildInsightsV2Request(t *testing.T) {
	t.Run("scopes openvsx extensions to vscode:open-vsx.org OSV ecosystem", func(t *testing.T) {
		pkg := &models.Package{
			Manifest: models.NewPackageManifestFromLocal(
				"/home/user/.cursor/extensions/extensions.json",
				models.EcosystemOpenVSXExtensions,
			),
			PackageDetails: models.NewPackageDetail(
				models.EcosystemOpenVSXExtensions,
				"llvm-vs-code-extensions.vscode-clangd",
				"0.4.0",
			),
		}

		req := buildInsightsV2Request(pkg)

		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_OPENVSX, req.GetPackageVersion().GetPackage().GetEcosystem())
		assert.Equal(t, "llvm-vs-code-extensions.vscode-clangd", req.GetPackageVersion().GetPackage().GetName())
		assert.Equal(t, "0.4.0", req.GetPackageVersion().GetVersion())
		assert.Equal(t, "vscode:open-vsx.org", req.GetOsvEcosystem())
	})

	t.Run("scopes vscode extensions to vscode OSV ecosystem", func(t *testing.T) {
		pkg := &models.Package{
			Manifest: models.NewPackageManifestFromLocal(
				"/home/user/.vscode/extensions/extensions.json",
				models.EcosystemVSCodeExtensions,
			),
			PackageDetails: models.NewPackageDetail(
				models.EcosystemVSCodeExtensions,
				"publisher.extension",
				"1.0.0",
			),
		}

		req := buildInsightsV2Request(pkg)

		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_VSCODE, req.GetPackageVersion().GetPackage().GetEcosystem())
		assert.Equal(t, "vscode", req.GetOsvEcosystem())
	})

	t.Run("passes raw distro ecosystem when protobuf enum is unspecified", func(t *testing.T) {
		ecosystem := "Alpine:v3.23"
		pkg := &models.Package{
			Manifest:       models.NewPackageManifestFromLocal("lib/apk/db/installed", ecosystem),
			PackageDetails: models.NewPackageDetail(ecosystem, "busybox", "1.36.1"),
		}

		req := buildInsightsV2Request(pkg)

		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, req.GetPackageVersion().GetPackage().GetEcosystem())
		assert.Equal(t, ecosystem, req.GetOsvEcosystem())
	})

	t.Run("does not set OSV ecosystem for npm packages", func(t *testing.T) {
		pkg := &models.Package{
			Manifest:       models.NewPackageManifestFromLocal("package-lock.json", models.EcosystemNpm),
			PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "lodash", "4.17.21"),
		}

		req := buildInsightsV2Request(pkg)

		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, req.GetPackageVersion().GetPackage().GetEcosystem())
		assert.Empty(t, req.GetOsvEcosystem())
	})
}

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

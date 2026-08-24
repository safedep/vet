package purl

import (
	"errors"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/models"
)

func TestParsePackageUrl(t *testing.T) {
	cases := []struct {
		name      string
		purl      string
		ecosystem lockfile.Ecosystem
		pkgName   string
		version   string
		err       error
	}{
		{
			"Parse a Gem PURL",
			"pkg:gem/nokogiri@7.5.1",
			lockfile.BundlerEcosystem,
			"nokogiri",
			"7.5.1",
			nil,
		},
		{
			"Invalid PURL Scheme",
			"http://invalid/purl",
			lockfile.Ecosystem(""),
			"",
			"",
			errors.New("purl scheme is not \"pkg\": \"http\""),
		},
		{
			"Invalid PURL Type",
			"pkg:unknown/a/b",
			lockfile.Ecosystem(""),
			"",
			"",
			errors.New("failed to map PURL type:unknown to known ecosystem"),
		},
		{
			"Parse GitHub Actions PURL",
			"pkg:actions/github/actions@v2",
			lockfile.Ecosystem(models.EcosystemGitHubActions),
			"github/actions",
			"v2",
			nil,
		},
		{
			"Parse vscode Extensions PURL",
			"pkg:vscode/streetsidesoftware.code-spell-checker@4.0.47",
			models.EcosystemVSCodeExtensions,
			"streetsidesoftware.code-spell-checker",
			"4.0.47",
			nil,
		},
		{
			"Parse vsix Extensions PURL",
			"pkg:vsix/streetsidesoftware.code-spell-checker@4.0.47",
			models.EcosystemVSCodeExtensions,
			"streetsidesoftware.code-spell-checker",
			"4.0.47",
			nil,
		},
		{
			"Parse vsx Extensions PURL",
			"pkg:vsx/streetsidesoftware.code-spell-checker@4.0.47",
			models.EcosystemVSCodeExtensions,
			"streetsidesoftware.code-spell-checker",
			"4.0.47",
			nil,
		},
		{
			"Parse openvsx Extensions PURL",
			"pkg:openvsx/streetsidesoftware.code-spell-checker@4.0.47",
			models.EcosystemOpenVSXExtensions,
			"streetsidesoftware.code-spell-checker",
			"4.0.47",
			nil,
		},
		{
			"Parse openvsx Extensions PURL with empty version",
			"pkg:openvsx/streetsidesoftware.code-spell-checker",
			models.EcosystemOpenVSXExtensions,
			"streetsidesoftware.code-spell-checker",
			"",
			nil,
		},
		{
			"Parse npm PURL with a dist tag",
			"pkg:npm/lodash@latest",
			lockfile.NpmEcosystem,
			"lodash",
			"latest",
			nil,
		},
		{
			"Reject npm PURL with a caret range",
			"pkg:npm/express@%5E4.0.0",
			lockfile.Ecosystem(""),
			"",
			"",
			errors.New("purl version is not a release: ^4.0.0"),
		},
		{
			"Reject PyPI PURL with a lower bound",
			"pkg:pypi/requests@%3E%3D2.28",
			lockfile.Ecosystem(""),
			"",
			"",
			errors.New("purl version is not a release: >=2.28"),
		},
		{
			"Reject Maven PURL with a version range",
			"pkg:maven/org.acme/lib@%5B1.0%2C2.0%29",
			lockfile.Ecosystem(""),
			"",
			"",
			errors.New("purl version is not a release: [1.0,2.0)"),
		},
		{
			"Parse PyPI PURL with a prerelease",
			"pkg:pypi/acme@1.0.0rc1",
			lockfile.PipEcosystem,
			"acme",
			"1.0.0rc1",
			nil,
		},
		{
			"Parse npm PURL with prerelease and build metadata",
			"pkg:npm/acme@1.0.0-beta.1%2Bbuild.7",
			lockfile.NpmEcosystem,
			"acme",
			"1.0.0-beta.1+build.7",
			nil,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r, err := ParsePackageUrl(test.purl)
			if test.err != nil {
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.Nil(t, err)

				assert.Equal(t, test.ecosystem, r.GetPackageDetails().Ecosystem)
				assert.Equal(t, test.pkgName, r.GetPackageDetails().Name)
				assert.Equal(t, test.version, r.GetPackageDetails().Version)
			}
		})
	}
}

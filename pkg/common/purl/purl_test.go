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
				assert.GreaterOrEqual(t, r.GetPackageDetails().Version, test.version)
			}
		})
	}
}

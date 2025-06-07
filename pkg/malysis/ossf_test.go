package malysis

import (
	"fmt"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func TestOpenSSFMaliciousPackageReportGenerator_relativeFilePath(t *testing.T) {
	cases := []struct {
		name        string
		ecosystem   packagev1.Ecosystem
		packageName string
		want        string
		wantErr     error
	}{
		{name: "npm", ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, packageName: "test", want: "osv/malicious/npm/test/MAL-0000-test.json", wantErr: nil},
		{name: "pypi", ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI, packageName: "test", want: "osv/malicious/pypi/test/MAL-0000-test.json", wantErr: nil},
		{name: "rubygems", ecosystem: packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS, packageName: "test", want: "osv/malicious/rubygems/test/MAL-0000-test.json", wantErr: nil},
		{name: "go", ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO, packageName: "github.com/test/test", want: "osv/malicious/go/github.com/test/test/MAL-0000-github.com-test-test.json", wantErr: nil},
		{name: "maven", ecosystem: packagev1.Ecosystem_ECOSYSTEM_MAVEN, packageName: "org.example.test:test", want: "osv/malicious/maven/org.example.test:test/MAL-0000-org.example.test-test.json", wantErr: nil},
		{name: "crates-io", ecosystem: packagev1.Ecosystem_ECOSYSTEM_CARGO, packageName: "test", want: "osv/malicious/crates-io/test/MAL-0000-test.json", wantErr: nil},
		{name: "unknown", ecosystem: packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, packageName: "test", want: "", wantErr: fmt.Errorf("unsupported ecosystem: %s", packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			generator := &openSSFMaliciousPackageReportGenerator{
				config: OpenSSFMaliciousPackageReportGeneratorConfig{},
			}

			got, err := generator.relativeFilePath(tc.ecosystem, tc.packageName)
			if tc.wantErr != nil {
				assert.ErrorContains(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

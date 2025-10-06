package malysis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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

func fileHasValidOSVReport(t *testing.T, filePath string) {
	jsonFile, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var vuln osvschema.Vulnerability
	err = json.Unmarshal(jsonFile, &vuln)
	if err != nil {
		t.Fatalf("failed to unmarshal file: %v", err)
	}

	assert.Empty(t, vuln.ID, "id should be empty")
	assert.NotEmpty(t, vuln.Published, "published should not be empty")
	assert.NotEmpty(t, vuln.Modified, "modified should not be empty")
	assert.NotEmpty(t, vuln.Affected, "affected should not be empty")
	assert.NotEmpty(t, vuln.References, "references should not be empty")
	assert.NotEmpty(t, vuln.Details, "details should not be empty")
	assert.NotEmpty(t, vuln.Summary, "summary should not be empty")
}

func TestOpenSSFMaliciousPackageReportGenerator_New(t *testing.T) {
	t.Run("dir does not exist", func(t *testing.T) {
		generator, err := NewOpenSSFMaliciousPackageReportGenerator(OpenSSFMaliciousPackageReportGeneratorConfig{
			Dir: "does-not-exist",
		})
		assert.Error(t, err)
		assert.Nil(t, generator)
	})

	t.Run("dir is not a directory", func(t *testing.T) {
		generator, err := NewOpenSSFMaliciousPackageReportGenerator(OpenSSFMaliciousPackageReportGeneratorConfig{
			Dir: "test.txt",
		})
		assert.Error(t, err)
		assert.Nil(t, generator)
	})

	t.Run("dir is a directory", func(t *testing.T) {
		generator, err := NewOpenSSFMaliciousPackageReportGenerator(OpenSSFMaliciousPackageReportGeneratorConfig{
			Dir: t.TempDir(),
		})
		assert.NoError(t, err)
		assert.NotNil(t, generator)
	})
}

func TestOpenSSFMaliciousPackageReportGenerator_GenerateReport(t *testing.T) {
	cases := []struct {
		name   string
		report *malysisv1pb.Report
		params OpenSSFMaliciousPackageReportParams
		setup  func(t *testing.T, dir string)
		assert func(t *testing.T, dir string, err error)
	}{
		{
			name: "report is generated in the expected path",
			report: &malysisv1pb.Report{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      "test",
					},
					Version: "1.0.0",
				},
				Inference: &malysisv1pb.Report_Inference{
					Summary: "This is a test report - Summary",
					Details: "This is a test report - Details",
				},
			},
			setup: func(t *testing.T, dir string) {
				_ = os.MkdirAll(dir, 0o755)
			},
			assert: func(t *testing.T, dir string, err error) {
				assert.NoError(t, err)
				filePath := filepath.Join(dir, "osv/malicious/npm/test/MAL-0000-test.json")
				assert.FileExists(t, filePath)

				fileHasValidOSVReport(t, filePath)
			},
		},
		{
			name: "default introduced version should be '0' not '0.0.0' when using range",
			report: &malysisv1pb.Report{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      "test-package",
					},
					Version: "1.0.0",
				},
				Inference: &malysisv1pb.Report_Inference{
					Summary: "Test malicious package",
					Details: "Test details",
				},
			},
			params: OpenSSFMaliciousPackageReportParams{
				// Deliberately leaving VersionIntroduced empty to test default
				UseRange: true, // Use range mode for this test
			},
			setup: func(t *testing.T, dir string) {
				_ = os.MkdirAll(dir, 0o755)
			},
			assert: func(t *testing.T, dir string, err error) {
				assert.NoError(t, err)
				filePath := filepath.Join(dir, "osv/malicious/npm/test-package/MAL-0000-test-package.json")
				assert.FileExists(t, filePath)

				// Read and validate the OSV report
				jsonFile, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var vuln osvschema.Vulnerability
				err = json.Unmarshal(jsonFile, &vuln)
				assert.NoError(t, err)

				// Verify the introduced version is "0" not "0.0.0"
				assert.Len(t, vuln.Affected, 1, "should have one affected package")
				assert.Len(t, vuln.Affected[0].Ranges, 1, "should have one range")
				assert.Len(t, vuln.Affected[0].Ranges[0].Events, 1, "should have one event")
				assert.Equal(t, "0", vuln.Affected[0].Ranges[0].Events[0].Introduced, "introduced version should be '0' according to OSV schema")
			},
		},
		{
			name: "default behavior should use explicit versions not ranges",
			report: &malysisv1pb.Report{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      "test-package-versions",
					},
					Version: "1.205.2",
				},
				Inference: &malysisv1pb.Report_Inference{
					Summary: "Test malicious package",
					Details: "Test details",
				},
			},
			params: OpenSSFMaliciousPackageReportParams{
				// UseRange is false by default
			},
			setup: func(t *testing.T, dir string) {
				_ = os.MkdirAll(dir, 0o755)
			},
			assert: func(t *testing.T, dir string, err error) {
				assert.NoError(t, err)
				filePath := filepath.Join(dir, "osv/malicious/npm/test-package-versions/MAL-0000-test-package-versions.json")
				assert.FileExists(t, filePath)

				// Read and validate the OSV report
				jsonFile, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var vuln osvschema.Vulnerability
				err = json.Unmarshal(jsonFile, &vuln)
				assert.NoError(t, err)

				// Verify explicit versions are used
				assert.Len(t, vuln.Affected, 1, "should have one affected package")
				assert.Len(t, vuln.Affected[0].Versions, 1, "should have one explicit version")
				assert.Equal(t, "1.205.2", vuln.Affected[0].Versions[0], "version should match package version")
				assert.Len(t, vuln.Affected[0].Ranges, 0, "should not have ranges when using explicit versions")
			},
		},
		{
			name: "PyPI ecosystem should use proper case and ECOSYSTEM range type",
			report: &malysisv1pb.Report{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
						Name:      "test-pypi-package",
					},
					Version: "1.0.0",
				},
				Inference: &malysisv1pb.Report_Inference{
					Summary: "Test malicious PyPI package",
					Details: "Test details for PyPI",
				},
			},
			params: OpenSSFMaliciousPackageReportParams{
				VersionIntroduced: "1.0.0",
				UseRange:          true, // Test range behavior for PyPI
			},
			setup: func(t *testing.T, dir string) {
				_ = os.MkdirAll(dir, 0o755)
			},
			assert: func(t *testing.T, dir string, err error) {
				assert.NoError(t, err)
				filePath := filepath.Join(dir, "osv/malicious/pypi/test-pypi-package/MAL-0000-test-pypi-package.json")
				assert.FileExists(t, filePath)

				// Read and validate the OSV report
				jsonFile, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var vuln osvschema.Vulnerability
				err = json.Unmarshal(jsonFile, &vuln)
				assert.NoError(t, err)

				// Verify PyPI ecosystem is properly cased
				assert.Len(t, vuln.Affected, 1, "should have one affected package")
				assert.Equal(t, "PyPI", vuln.Affected[0].Package.Ecosystem, "ecosystem should be 'PyPI' with proper case")
				assert.Equal(t, "test-pypi-package", vuln.Affected[0].Package.Name, "package name should match")

				// Verify ECOSYSTEM range type is used for PyPI
				assert.Len(t, vuln.Affected[0].Ranges, 1, "should have one range")
				assert.Equal(t, osvschema.RangeEcosystem, vuln.Affected[0].Ranges[0].Type, "PyPI should use ECOSYSTEM range type")

				// Verify version information
				assert.Len(t, vuln.Affected[0].Ranges[0].Events, 1, "should have one event")
				assert.Equal(t, "1.0.0", vuln.Affected[0].Ranges[0].Events[0].Introduced, "introduced version should match")
			},
		},
		{
			name: "NPM ecosystem should use proper case and SEMVER range type",
			report: &malysisv1pb.Report{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      "test-npm-package",
					},
					Version: "1.0.0",
				},
				Inference: &malysisv1pb.Report_Inference{
					Summary: "Test malicious NPM package",
					Details: "Test details for NPM",
				},
			},
			params: OpenSSFMaliciousPackageReportParams{
				VersionIntroduced: "1.0.0",
				UseRange:          true, // Test range behavior for NPM
			},
			setup: func(t *testing.T, dir string) {
				_ = os.MkdirAll(dir, 0o755)
			},
			assert: func(t *testing.T, dir string, err error) {
				assert.NoError(t, err)
				filePath := filepath.Join(dir, "osv/malicious/npm/test-npm-package/MAL-0000-test-npm-package.json")
				assert.FileExists(t, filePath)

				// Read and validate the OSV report
				jsonFile, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var vuln osvschema.Vulnerability
				err = json.Unmarshal(jsonFile, &vuln)
				assert.NoError(t, err)

				// Verify NPM ecosystem name
				assert.Len(t, vuln.Affected, 1, "should have one affected package")
				assert.Equal(t, "npm", vuln.Affected[0].Package.Ecosystem, "ecosystem should be 'npm'")
				assert.Equal(t, "test-npm-package", vuln.Affected[0].Package.Name, "package name should match")

				// Verify SEMVER range type is used for NPM
				assert.Len(t, vuln.Affected[0].Ranges, 1, "should have one range")
				assert.Equal(t, osvschema.RangeSemVer, vuln.Affected[0].Ranges[0].Type, "NPM should use SEMVER range type")

				// Verify version information
				assert.Len(t, vuln.Affected[0].Ranges[0].Events, 1, "should have one event")
				assert.Equal(t, "1.0.0", vuln.Affected[0].Ranges[0].Events[0].Introduced, "introduced version should match")
			},
		},
		{
			name: "custom reference URL should be used when provided",
			report: &malysisv1pb.Report{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      "test-custom-url",
					},
					Version: "1.0.0",
				},
				Inference: &malysisv1pb.Report_Inference{
					Summary: "Test malicious package with custom URL",
					Details: "Test details",
				},
				ReportId: "test-report-id",
			},
			params: OpenSSFMaliciousPackageReportParams{
				ReferenceURL: "https://blog.example.com/malware-reports",
			},
			setup: func(t *testing.T, dir string) {
				_ = os.MkdirAll(dir, 0o755)
			},
			assert: func(t *testing.T, dir string, err error) {
				assert.NoError(t, err)
				filePath := filepath.Join(dir, "osv/malicious/npm/test-custom-url/MAL-0000-test-custom-url.json")
				assert.FileExists(t, filePath)

				// Read and validate the OSV report
				jsonFile, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var vuln osvschema.Vulnerability
				err = json.Unmarshal(jsonFile, &vuln)
				assert.NoError(t, err)

				// Verify custom reference URL is used
				assert.Len(t, vuln.References, 1, "should have one reference")
				assert.Equal(t, "https://blog.example.com/malware-reports", vuln.References[0].URL, "should use custom reference URL")

				// Verify explicit versions are used (default behavior)
				assert.Len(t, vuln.Affected, 1, "should have one affected package")
				assert.Len(t, vuln.Affected[0].Versions, 1, "should have one explicit version")
				assert.Equal(t, "1.0.0", vuln.Affected[0].Versions[0], "version should match package version")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Cleanup(func() {
				// We don't care about the error here because we are using a temp dir
				_ = os.RemoveAll(tmpDir)
			})

			if tc.setup != nil {
				tc.setup(t, tmpDir)
			}

			generator, err := NewOpenSSFMaliciousPackageReportGenerator(OpenSSFMaliciousPackageReportGeneratorConfig{
				Dir: tmpDir,
			})
			assert.NoError(t, err)
			assert.NotNil(t, generator)

			err = generator.GenerateReport(context.Background(), tc.report, tc.params)
			tc.assert(t, tmpDir, err)
		})
	}
}

package reporter

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestManifestRelativePath(t *testing.T) {
	testCases := []struct {
		name string

		pkg               *models.Package
		currentWorkingDir string

		expectError          bool
		expectedRelativePath string
	}{
		{
			name: "valid current working directory",
			pkg: &models.Package{
				Manifest: &models.PackageManifest{
					Path: "/home/user/work/company/project/source/package-lock.json",
				},
			},
			currentWorkingDir:    "/home/user/work/company/project/source",
			expectError:          false,
			expectedRelativePath: "package-lock.json",
		},
		{
			name: "valid current working directory with sub dir manifest path",
			pkg: &models.Package{
				Manifest: &models.PackageManifest{
					Path: "/home/user/work/company/project/source/apps/cli/go.mod",
				},
			},
			currentWorkingDir:    "/home/user/work/company/project/source",
			expectError:          false,
			expectedRelativePath: "apps/cli/go.mod",
		},
		{
			name: "empty current working directory - error on os.Getwd()",
			pkg: &models.Package{
				Manifest: &models.PackageManifest{
					Path: "/home/user/work/company/project/source/package-lock.json",
				},
			},
			currentWorkingDir: "", // os.Getwd() failed, then currentWorkingDir = ""
			expectError:       true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := &summaryReporter{}
			relativePath, err := r.packageManifestRelativePath(test.pkg, test.currentWorkingDir)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, relativePath, test.expectedRelativePath)
			}
		})
	}
}

package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManifestRelativePath(t *testing.T) {
	testCases := []struct {
		name string

		currentWorkingDir string
		manifestFullPath  string

		expectError          bool
		expectedRelativePath string
	}{
		{
			name:              "valid current working directory",
			currentWorkingDir: "/home/user/work/company/project/source",
			manifestFullPath:  "/home/user/work/company/project/source/package-lock.json",

			expectError:          false,
			expectedRelativePath: "package-lock.json",
		},
		{
			name:              "valid current working directory with sub dir manifest path",
			currentWorkingDir: "/home/user/work/company/project/source",
			manifestFullPath:  "/home/user/work/company/project/source/apps/cli/go.mod",

			expectError:          false,
			expectedRelativePath: "apps/cli/go.mod",
		},
		{
			name:              "empty current working directory - error on os.Getwd()",
			currentWorkingDir: "", // os.Getwd() failed, then currentWorkingDir = ""
			manifestFullPath:  "/home/user/work/company/project/source/package-lock.json",
			expectError:       true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := &summaryReporter{}
			relativePath, err := r.packageManifestRelativePath(test.currentWorkingDir, test.manifestFullPath)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, relativePath, test.expectedRelativePath)
			}
		})
	}
}

func TestRenderInternalErrorMessages(t *testing.T) {
	t.Run("when quota exceeded error count is greater than 0", func(t *testing.T) {
		t.Parallel()

		r := &summaryReporter{}
		r.summary.internalErrors.malwareAnalysisQuotaLimitErrorCount = 5

		expectedErrorMessage := "You have reached your quota for on-demand malicious package scanning. 5 on-demand analysis requests were denied. Please see safedep.io/pricing for upgrade."

		actualErrorMessage := renderInternalErrroMessages(5)

		assert.Equal(t, expectedErrorMessage, actualErrorMessage)
	})
}

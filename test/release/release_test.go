// Package release_test checks the rules that keep a vet v2 build out of the
// release channels of vet v1. Users of v1 run the latest container image,
// and the vet-action, the Homebrew formula and mise read the latest GitHub
// release.
package release_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const root = "../.."

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, path))
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, yaml.Unmarshal(data, &out))
	return out
}

func workflows(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, ".github/workflows/*.yml"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	return files
}

func TestGoreleaserPublishesAPreRelease(t *testing.T) {
	cfg := readYAML(t, ".goreleaser.yaml")

	release, ok := cfg["release"].(map[string]any)
	require.True(t, ok, "the release section is missing")
	assert.Equal(t, "true", release["prerelease"])
	assert.Equal(t, "false", release["make_latest"])
	assert.NotEqual(t, true, release["disable"])

	casks, ok := cfg["homebrew_casks"].([]any)
	require.True(t, ok, "the homebrew_casks section is missing")
	require.Len(t, casks, 1)
	cask, ok := casks[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "vet@edge", cask["name"])
	assert.Contains(t, cask["conflicts"], map[string]any{"cask": "vet"})

	for _, key := range []string{"brews", "dockers", "dockers_v2", "docker_manifests", "npms"} {
		assert.NotContains(t, cfg, key, "a %s section can write a v1 channel", key)
	}
}

func TestReleaseRunsOnlyAfterAMerge(t *testing.T) {
	wf := readYAML(t, ".github/workflows/release-edge.yml")

	on, ok := wf["on"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, on, 1, "a merge to v2 is the only trigger")
	push, ok := on["push"].(map[string]any)
	require.True(t, ok, "the trigger is not a push")
	assert.Equal(t, []any{"v2"}, push["branches"])
	assert.NotContains(t, push, "tags")

	jobs, ok := wf["jobs"].(map[string]any)
	require.True(t, ok)
	job, ok := jobs["release"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "v2-edge", job["environment"])
}

// A tag workflow of v1, such as goreleaser.yml or container.yml, can come
// back with a merge from main. It would publish the v2 alpha tag to v1.
func TestNoWorkflowRunsOnATag(t *testing.T) {
	for _, file := range workflows(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			wf := readYAML(t, filepath.Join(".github/workflows", filepath.Base(file)))
			on, ok := wf["on"].(map[string]any)
			if !ok {
				return
			}
			push, ok := on["push"].(map[string]any)
			if !ok {
				return
			}
			assert.NotContains(t, push, "tags")
		})
	}
}

// A line may name the latest image only to read its digest.
func TestNoWorkflowWritesTheLatestImage(t *testing.T) {
	scripts, err := filepath.Glob(filepath.Join(root, ".github/scripts/*"))
	require.NoError(t, err)
	for _, file := range append(workflows(t), scripts...) {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, ":latest") {
				assert.Contains(t, line, "imagetools inspect", "%s:%d names the latest image", filepath.Base(file), i+1)
			}
		}
	}
}

func TestCrossImageHasTheGoVersionOfGoMod(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	require.NoError(t, err)
	goVersion := regexp.MustCompile(`(?m)^go (\S+)$`).FindSubmatch(mod)
	require.NotNil(t, goVersion)

	script, err := os.ReadFile(filepath.Join(root, ".github/scripts/goreleaser-cross.sh"))
	require.NoError(t, err)
	image := regexp.MustCompile(`goreleaser-cross:v(\d+\.\d+\.\d+)-v[\d.]+@sha256:[0-9a-f]{64}"`).FindSubmatch(script)
	require.NotNil(t, image, "the image needs a Go version tag and a digest")

	assert.Equal(t, string(goVersion[1]), string(image[1]))
}

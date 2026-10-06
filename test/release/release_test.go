// Package release_test checks the rules that keep a vet v2 build out of the
// release channels of vet v1. Users of v1 run the latest container image,
// and the vet-action, the Homebrew formula and mise read the latest GitHub
// release.
package release_test

import (
	"fmt"
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
	var files []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		found, err := filepath.Glob(filepath.Join(root, ".github/workflows", pattern))
		require.NoError(t, err)
		files = append(files, found...)
	}
	require.NotEmpty(t, files)
	return files
}

// triggers returns the events of a workflow and their filters. A workflow
// can write "on" as a string, a list or a map.
func triggers(t *testing.T, wf map[string]any) map[string]any {
	t.Helper()
	switch on := wf["on"].(type) {
	case string:
		return map[string]any{on: nil}
	case []any:
		out := map[string]any{}
		for _, event := range on {
			name, ok := event.(string)
			require.True(t, ok)
			out[name] = nil
		}
		return out
	case map[string]any:
		return on
	default:
		require.Failf(t, "no trigger", "the workflow has no on key")
		return nil
	}
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

	assert.NotContains(t, cask, "skip_upload")
	repo, ok := cask["repository"].(map[string]any)
	require.True(t, ok, "the cask has no repository")
	assert.Equal(t, "safedep", repo["owner"])
	assert.Equal(t, "homebrew-tap", repo["name"])

	// A new section can publish to a new place, such as a container
	// registry, npm or a package index. Add it here only after a check that
	// it cannot write a v1 channel.
	allowed := []string{
		"version", "project_name", "before", "builds", "universal_binaries", "archives",
		"checksum", "snapshot", "changelog", "release", "homebrew_casks",
	}
	for key := range cfg {
		assert.Contains(t, allowed, key, "the section %s can publish to a new place", key)
	}
}

func TestReleaseRunsOnlyAfterAMerge(t *testing.T) {
	wf := readYAML(t, ".github/workflows/release-edge.yml")

	on := triggers(t, wf)
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
// back with a merge from main. It would publish the v2 alpha tag to v1. A
// push trigger with no branch filter also runs on a tag.
func TestNoWorkflowRunsOnATag(t *testing.T) {
	for _, file := range workflows(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			on := triggers(t, readYAML(t, filepath.Join(".github/workflows", filepath.Base(file))))
			assert.NotContains(t, on, "release")
			assert.NotContains(t, on, "create")
			push, ok := on["push"]
			if !ok {
				return
			}
			filter, ok := push.(map[string]any)
			require.True(t, ok, "a push trigger with no filter runs on a tag")
			assert.NotContains(t, filter, "tags")
			assert.NotContains(t, filter, "tags-ignore")
			assert.True(t, filter["branches"] != nil || filter["branches-ignore"] != nil,
				"a push trigger with no branch filter runs on a tag")
		})
	}
}

// A line may name the latest image only to read its digest. The
// docker/metadata-action writes the latest tag with value=latest or
// latest=true, and with latest=auto on a tag.
func TestNoWorkflowWritesTheLatestImage(t *testing.T) {
	latest := regexp.MustCompile(`:latest\b|value=latest\b|latest=(true|auto)\b`)
	scripts, err := filepath.Glob(filepath.Join(root, ".github/scripts/*"))
	require.NoError(t, err)
	for _, file := range append(workflows(t), scripts...) {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		for i, line := range strings.Split(string(data), "\n") {
			if latest.MatchString(line) {
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

// The latest release of safedep/vet is a v1 release. The action lists the
// releases and picks a v2 tag. gh release download with no tag also takes
// the latest release, so install.sh always passes a tag.
func TestActionNeverReadsTheLatestRelease(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(root, "action", "*"))
	require.NoError(t, err)
	files = append(files, filepath.Join(root, "action.yml"))
	download := regexp.MustCompile(`gh release download "\$tag" `)
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		info, err := os.Stat(file)
		require.NoError(t, err)
		if info.IsDir() {
			continue
		}
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		for i, line := range strings.Split(string(data), "\n") {
			name := fmt.Sprintf("%s:%d", filepath.Base(file), i+1)
			assert.NotContains(t, line, "releases/latest", name)
			assert.NotContains(t, line, "--latest", name)
			if strings.Contains(line, "gh release download") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				assert.Regexp(t, download, line, "%s downloads with no explicit tag", name)
			}
		}
	}
}

// The action test runs on each pull request that changes the action. It
// may read the repository and write the comment of the pull request. It
// writes no release, no tag and no image.
func TestActionTestWritesNoRelease(t *testing.T) {
	wf := readYAML(t, ".github/workflows/action-test.yml")
	assert.Equal(t, []string{"pull_request"}, keys(triggers(t, wf)))

	allowed := map[string]string{"contents": "read", "pull-requests": "write"}
	check := func(where string, perms any) {
		m, ok := perms.(map[string]any)
		require.True(t, ok, "%s sets no permissions map", where)
		for scope, level := range m {
			if level == "read" || level == "none" {
				continue
			}
			assert.Equal(t, allowed[scope], level, "%s: %s: %v", where, scope, level)
		}
	}
	check("the workflow", wf["permissions"])
	jobs, ok := wf["jobs"].(map[string]any)
	require.True(t, ok)
	for name, job := range jobs {
		j, ok := job.(map[string]any)
		require.True(t, ok)
		if perms, ok := j["permissions"]; ok {
			check(name, perms)
		}
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

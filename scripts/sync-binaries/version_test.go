package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeDir creates a directory for test fixtures.
// 0o755 is the conventional permission for directories that need traversal.
func makeDir(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(path, 0o755)) //nolint:gosec
}

// writeTestFile writes a file for test fixtures.
// 0o644 is the conventional permission for config files like package.json.
func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, 0o644)) //nolint:gosec
}

func writePkgJSON(t *testing.T, dir, name string, content map[string]any) string {
	t.Helper()
	pkgDir := filepath.Join(dir, name)
	makeDir(t, pkgDir)
	data, err := json.MarshalIndent(content, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(pkgDir, "package.json")
	writeTestFile(t, path, append(data, '\n'))
	return path
}

func readVersion(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var pkg map[string]any
	require.NoError(t, json.Unmarshal(data, &pkg))
	v, _ := pkg["version"].(string)
	return v
}

func TestSetPackageVersions(t *testing.T) {
	t.Run("sets version in all non-private packages", func(t *testing.T) {
		dir := t.TempDir()
		pathA := writePkgJSON(t, dir, "pkg-a", map[string]any{"name": "pkg-a", "version": "0.0.0"})
		pathB := writePkgJSON(t, dir, "pkg-b", map[string]any{"name": "pkg-b", "version": "0.0.0"})

		require.NoError(t, setPackageVersions(dir, "1.2.3"))

		assert.Equal(t, "1.2.3", readVersion(t, pathA))
		assert.Equal(t, "1.2.3", readVersion(t, pathB))
	})

	t.Run("skips private packages", func(t *testing.T) {
		dir := t.TempDir()
		pathPriv := writePkgJSON(t, dir, "private-pkg", map[string]any{
			"name":    "private-pkg",
			"version": "0.0.0",
			"private": true,
		})
		pathPub := writePkgJSON(t, dir, "public-pkg", map[string]any{"name": "public-pkg", "version": "0.0.0"})

		require.NoError(t, setPackageVersions(dir, "2.0.0"))

		assert.Equal(t, "0.0.0", readVersion(t, pathPriv))
		assert.Equal(t, "2.0.0", readVersion(t, pathPub))
	})

	t.Run("skips subdirectories without package.json", func(t *testing.T) {
		dir := t.TempDir()
		makeDir(t, filepath.Join(dir, "no-pkg-json"))
		pathA := writePkgJSON(t, dir, "pkg-a", map[string]any{"name": "pkg-a", "version": "0.0.0"})

		require.NoError(t, setPackageVersions(dir, "3.0.0"))

		assert.Equal(t, "3.0.0", readVersion(t, pathA))
	})

	t.Run("rejects invalid semver", func(t *testing.T) {
		err := setPackageVersions(t.TempDir(), "not-a-version")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version")
	})

	t.Run("returns error when packages dir is missing", func(t *testing.T) {
		err := setPackageVersions("/nonexistent/path", "1.0.0")
		require.Error(t, err)
	})
}

func writeBinary(t *testing.T, dir, pkgName, binName string) {
	t.Helper()
	binDir := filepath.Join(dir, pkgName, "bin")
	makeDir(t, binDir)
	// 0o755: binary files need execute permission.
	require.NoError(t, os.WriteFile(filepath.Join(binDir, binName), []byte("binary"), 0o755)) //nolint:gosec
}

func TestVerifyPackageBins(t *testing.T) {
	t.Run("passes when all platform packages have binaries", func(t *testing.T) {
		dir := t.TempDir()
		writePkgJSON(t, dir, "cli-linux-x64", map[string]any{
			"name": "cli-linux-x64", "version": "0.0.0", "os": []string{"linux"},
		})
		writeBinary(t, dir, "cli-linux-x64", "pmg")

		writePkgJSON(t, dir, "cli-darwin-arm64", map[string]any{
			"name": "cli-darwin-arm64", "version": "0.0.0", "os": []string{"darwin"},
		})
		writeBinary(t, dir, "cli-darwin-arm64", "pmg")

		require.NoError(t, verifyPackageBins(dir))
	})

	t.Run("fails when a platform package has an empty bin/", func(t *testing.T) {
		dir := t.TempDir()
		writePkgJSON(t, dir, "cli-linux-x64", map[string]any{
			"name": "cli-linux-x64", "version": "0.0.0", "os": []string{"linux"},
		})
		makeDir(t, filepath.Join(dir, "cli-linux-x64", "bin"))

		err := verifyPackageBins(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cli-linux-x64")
	})

	t.Run("fails when a platform package has no bin/ directory", func(t *testing.T) {
		dir := t.TempDir()
		writePkgJSON(t, dir, "cli-linux-x64", map[string]any{
			"name": "cli-linux-x64", "version": "0.0.0", "os": []string{"linux"},
		})

		err := verifyPackageBins(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cli-linux-x64")
	})

	t.Run("skips meta packages without os field", func(t *testing.T) {
		dir := t.TempDir()
		writePkgJSON(t, dir, "cli", map[string]any{
			"name": "cli", "version": "0.0.0",
		})

		require.NoError(t, verifyPackageBins(dir))
	})

	t.Run("skips private packages", func(t *testing.T) {
		dir := t.TempDir()
		writePkgJSON(t, dir, "cli-private", map[string]any{
			"name": "cli-private", "version": "0.0.0", "os": []string{"linux"}, "private": true,
		})

		require.NoError(t, verifyPackageBins(dir))
	})

	t.Run("reports multiple missing packages", func(t *testing.T) {
		dir := t.TempDir()
		writePkgJSON(t, dir, "cli-linux-x64", map[string]any{
			"name": "cli-linux-x64", "version": "0.0.0", "os": []string{"linux"},
		})
		writePkgJSON(t, dir, "cli-darwin-x64", map[string]any{
			"name": "cli-darwin-x64", "version": "0.0.0", "os": []string{"darwin"},
		})

		err := verifyPackageBins(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cli-linux-x64")
		assert.Contains(t, err.Error(), "cli-darwin-x64")
	})
}

func TestSetVersionInPackageJSON(t *testing.T) {
	t.Run("writes version field", func(t *testing.T) {
		dir := t.TempDir()
		path := writePkgJSON(t, dir, "pkg", map[string]any{"name": "pkg", "version": "0.0.0"})

		require.NoError(t, setVersionInPackageJSON(filepath.Join(dir, "pkg", "package.json"), "4.5.6"))

		assert.Equal(t, "4.5.6", readVersion(t, path))
	})

	t.Run("skips private package", func(t *testing.T) {
		dir := t.TempDir()
		path := writePkgJSON(t, dir, "pkg", map[string]any{"name": "pkg", "version": "0.0.0", "private": true})

		require.NoError(t, setVersionInPackageJSON(filepath.Join(dir, "pkg", "package.json"), "4.5.6"))

		assert.Equal(t, "0.0.0", readVersion(t, path))
	})

	t.Run("missing file is a no-op", func(t *testing.T) {
		err := setVersionInPackageJSON("/nonexistent/package.json", "1.0.0")
		require.NoError(t, err)
	})

	t.Run("preserves inline array formatting", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "pkg", "package.json")
		makeDir(t, filepath.Dir(path))

		original := `{
  "name": "pkg",
  "version": "0.0.0",
  "os": ["linux"],
  "cpu": ["x64"],
  "files": ["bin/**"]
}
`
		writeTestFile(t, path, []byte(original))

		require.NoError(t, setVersionInPackageJSON(path, "1.2.3"))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		content := string(data)

		assert.Contains(t, content, `"version": "1.2.3"`)
		assert.Contains(t, content, `"os": ["linux"]`)
		assert.Contains(t, content, `"cpu": ["x64"]`)
		assert.Contains(t, content, `"files": ["bin/**"]`)
	})

	t.Run("does not match version inside a string value", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "pkg", "package.json")
		makeDir(t, filepath.Dir(path))

		original := "{\n  \"name\": \"pkg\",\n  \"version\": \"0.0.0\",\n  \"description\": \"see \\\"version\\\": \\\"1.0.0\\\" in docs\"\n}\n"
		writeTestFile(t, path, []byte(original))

		require.NoError(t, setVersionInPackageJSON(path, "2.0.0"))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		content := string(data)

		assert.Contains(t, content, `"version": "2.0.0"`)
		assert.Contains(t, content, "\"description\": \"see \\\"version\\\": \\\"1.0.0\\\" in docs\"")
	})
}

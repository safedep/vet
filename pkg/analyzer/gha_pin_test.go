package analyzer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/pkg/models"
)

type mockSHAResolver struct {
	mapping map[string]string
}

func (m *mockSHAResolver) ResolveSHA(_ context.Context, owner, repo, ref string) (string, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	if sha, ok := m.mapping[key]; ok {
		return sha, nil
	}
	return "", fmt.Errorf("unknown ref: %s", key)
}

type countingSHAResolver struct {
	mapping   map[string]string
	callCount int
}

func (m *countingSHAResolver) ResolveSHA(_ context.Context, owner, repo, ref string) (string, error) {
	m.callCount++
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	if sha, ok := m.mapping[key]; ok {
		return sha, nil
	}
	return "", fmt.Errorf("unknown ref: %s", key)
}

func newTestGHAPinAnalyzer(resolver ghaSHAResolver) *ghaPinAnalyzer {
	return &ghaPinAnalyzer{
		resolver: resolver,
	}
}

func noopHandler(_ *AnalyzerEvent) error {
	return nil
}

func copyFixture(t *testing.T, fixturePath string) string {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), filepath.Base(fixturePath))
	err = os.WriteFile(tmpFile, data, 0o644)
	require.NoError(t, err)
	return tmpFile
}

func TestFindUsesNodes(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
      - name: Run tests
        run: go test ./...
`
	doc := &yaml.Node{}
	err := yaml.Unmarshal([]byte(input), doc)
	require.NoError(t, err)

	nodes := newTestGHAPinAnalyzer(&mockSHAResolver{}).findUsesNodes(doc)
	assert.Len(t, nodes, 2)
	assert.Equal(t, "actions/checkout@v3", nodes[0].Value)
	assert.Equal(t, "actions/setup-go@v4", nodes[1].Value)
}

func TestFindUsesNodes_AlreadyPinned(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
`
	doc := &yaml.Node{}
	err := yaml.Unmarshal([]byte(input), doc)
	require.NoError(t, err)

	nodes := newTestGHAPinAnalyzer(&mockSHAResolver{}).findUsesNodes(doc)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608", nodes[0].Value)
}

func TestGHAPinAnalyzer_SkipsNonGHAManifest(t *testing.T) {
	a := newTestGHAPinAnalyzer(&mockSHAResolver{})
	manifest := models.NewPackageManifestFromLocal("/tmp/package.json", models.EcosystemNpm)

	err := a.Analyze(manifest, noopHandler)
	assert.NoError(t, err)
	assert.Equal(t, 0, a.pinCount)
}

func TestGHAPinAnalyzer_PinsUnpinnedActions(t *testing.T) {
	tmpFile := copyFixture(t, "fixtures/gha_pin_unpinned.yml")

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v3": "abc123def456abc123def456abc123def456abc1",
			"actions/setup-go@v4": "def789abc123def789abc123def789abc123def7",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	var events []*AnalyzerEvent
	handler := func(event *AnalyzerEvent) error {
		events = append(events, event)
		return nil
	}

	err := a.Analyze(manifest, handler)
	require.NoError(t, err)
	assert.Equal(t, 2, a.pinCount)
	assert.Len(t, events, 2)

	// Verify the file was modified
	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	assert.Contains(t, content, "actions/checkout@abc123def456abc123def456abc123def456abc1")
	assert.Contains(t, content, "actions/setup-go@def789abc123def789abc123def789abc123def7")
	// Verify inline comments with original tags
	assert.Contains(t, content, "# v3")
	assert.Contains(t, content, "# v4")
}

func TestGHAPinAnalyzer_SkipsAlreadyPinned(t *testing.T) {
	tmpFile := copyFixture(t, "fixtures/gha_pin_already_pinned.yml")

	a := newTestGHAPinAnalyzer(&mockSHAResolver{})
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err := a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 0, a.pinCount)
}

func TestGHAPinAnalyzer_MixedPinnedAndUnpinned(t *testing.T) {
	tmpFile := copyFixture(t, "fixtures/gha_pin_mixed.yml")

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"actions/setup-node@v3": "aaa111bbb222ccc333ddd444eee555fff666aaa1",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err := a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 1, a.pinCount)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	// Already pinned action should remain unchanged
	assert.Contains(t, content, "actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608")
	// Newly pinned action
	assert.Contains(t, content, "actions/setup-node@aaa111bbb222ccc333ddd444eee555fff666aaa1")
	assert.Contains(t, content, "# v3")
}

func TestGHAPinAnalyzer_PreservesComments(t *testing.T) {
	tmpFile := copyFixture(t, "fixtures/gha_pin_unpinned.yml")

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v3": "abc123def456abc123def456abc123def456abc1",
			"actions/setup-go@v4": "def789abc123def789abc123def789abc123def7",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err := a.Analyze(manifest, noopHandler)
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	// Original comments should be preserved
	assert.Contains(t, content, "# CI workflow for testing")
	assert.Contains(t, content, "# Checkout the code")
}

func TestGHAPinAnalyzer_ActionWithSubpath(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials/assume-role@v2
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"aws-actions/configure-aws-credentials@v2": "aabbccdd11223344556677889900aabbccdd1122",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 1, a.pinCount)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	// Should preserve the subpath
	assert.Contains(t, content, "aws-actions/configure-aws-credentials/assume-role@aabbccdd11223344556677889900aabbccdd1122")
	assert.Contains(t, content, "# v2")
}

func TestGHAPinAnalyzer_ContinuesOnResolutionError(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: unknown/action@v1
      - uses: actions/checkout@v3
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			// Only checkout resolves, unknown/action will fail
			"actions/checkout@v3": "abc123def456abc123def456abc123def456abc1",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	// Only one was pinnable
	assert.Equal(t, 1, a.pinCount)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	// The unknown action should remain as-is
	assert.Contains(t, content, "unknown/action@v1")
	// Checkout should be pinned
	assert.Contains(t, content, "actions/checkout@abc123def456abc123def456abc123def456abc1")
}

func TestGHAPinAnalyzer_PreservesExistingLineComment(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3 # required for CI
      - uses: actions/setup-go@v4
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v3": "abc123def456abc123def456abc123def456abc1",
			"actions/setup-go@v4": "def789abc123def789abc123def789abc123def7",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 2, a.pinCount)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	// Existing comment should be preserved with pinned-from appended
	assert.Contains(t, content, "# required for CI; pinned-from=v3")
	// No existing comment should just get the ref
	assert.Contains(t, content, "# v4")
}

func TestGHAPinAnalyzer_NoUsesInWorkflow(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: go test ./...
      - name: Build
        run: go build ./...
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	a := newTestGHAPinAnalyzer(&mockSHAResolver{})
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 0, a.pinCount)

	// File should remain unchanged
	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, input, string(data))
}

func TestGHAPinAnalyzer_DockerAndLocalActionsIgnored(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.8
      - uses: docker://ghcr.io/owner/image:latest
      - uses: docker://alpine@sha256:a3d7e1a2b0e1f4e5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9
      - uses: docker://ghcr.io/owner/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
      - uses: ./local-action
      - uses: ./.github/actions/my-action
      - uses: actions/checkout@v3
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v3": "abc123def456abc123def456abc123def456abc1",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 1, a.pinCount)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	// Docker references (tag and digest forms) should remain untouched
	assert.Contains(t, content, "docker://alpine:3.8")
	assert.Contains(t, content, "docker://ghcr.io/owner/image:latest")
	assert.Contains(t, content, "docker://alpine@sha256:")
	assert.Contains(t, content, "docker://ghcr.io/owner/image@sha256:")
	// Local actions should remain untouched
	assert.Contains(t, content, "./local-action")
	assert.Contains(t, content, "./.github/actions/my-action")
	// Only the regular action should be pinned
	assert.Contains(t, content, "actions/checkout@abc123def456abc123def456abc123def456abc1")
}

func TestGHAPinAnalyzer_SHA256AlreadyPinned(t *testing.T) {
	sha256 := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	input := fmt.Sprintf(`name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s
`, sha256)
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	a := newTestGHAPinAnalyzer(&mockSHAResolver{})
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 0, a.pinCount)
}

func TestGHAPinAnalyzer_MultipleJobsMultipleSteps(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: golangci/golangci-lint-action@v3
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	resolver := &mockSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v3":              "abc123def456abc123def456abc123def456abc1",
			"actions/setup-go@v4":              "def789abc123def789abc123def789abc123def7",
			"golangci/golangci-lint-action@v3": "111222333444555666777888999000aaabbbccc1",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	// checkout@v3 appears twice + setup-go@v4 + golangci-lint-action@v3 = 4
	assert.Equal(t, 4, a.pinCount)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	content := string(data)

	assert.Contains(t, content, "actions/checkout@abc123def456abc123def456abc123def456abc1")
	assert.Contains(t, content, "actions/setup-go@def789abc123def789abc123def789abc123def7")
	assert.Contains(t, content, "golangci/golangci-lint-action@111222333444555666777888999000aaabbbccc1")
	// Already-pinned action in deploy job should be untouched
	assert.Contains(t, content, "actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608")
}

func TestGHAPinAnalyzer_CachesPreviouslyResolvedSHAs(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
`
	tmpFile := filepath.Join(t.TempDir(), "workflow.yml")
	err := os.WriteFile(tmpFile, []byte(input), 0o644)
	require.NoError(t, err)

	resolver := &countingSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v3": "abc123def456abc123def456abc123def456abc1",
		},
	}

	a := newTestGHAPinAnalyzer(resolver)
	manifest := models.NewPackageManifestFromLocal(tmpFile, models.EcosystemGitHubActions)
	manifest.Path = tmpFile

	err = a.Analyze(manifest, noopHandler)
	require.NoError(t, err)
	assert.Equal(t, 3, a.pinCount)

	// Resolver should only be called once despite 3 identical refs
	assert.Equal(t, 1, resolver.callCount)
}

func TestGhaUsesRegex(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		match      bool
		actionPath string
		ref        string
	}{
		{
			name:       "standard owner/repo@tag",
			input:      "actions/checkout@v3",
			match:      true,
			actionPath: "actions/checkout",
			ref:        "v3",
		},
		{
			name:       "owner/repo@branch",
			input:      "actions/checkout@main",
			match:      true,
			actionPath: "actions/checkout",
			ref:        "main",
		},
		{
			name:       "owner/repo@semver tag",
			input:      "actions/setup-go@v4.1.0",
			match:      true,
			actionPath: "actions/setup-go",
			ref:        "v4.1.0",
		},
		{
			name:       "owner/repo@commit SHA",
			input:      "actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608",
			match:      true,
			actionPath: "actions/checkout",
			ref:        "8ade135a41bc03ea155e62e844d188df1ea18608",
		},
		{
			name:       "owner/repo/subpath@tag",
			input:      "aws-actions/configure-aws-credentials/assume-role@v2",
			match:      true,
			actionPath: "aws-actions/configure-aws-credentials/assume-role",
			ref:        "v2",
		},
		{
			name:       "owner/repo/deep/subpath@tag",
			input:      "org/repo/path/to/action@v1",
			match:      true,
			actionPath: "org/repo/path/to/action",
			ref:        "v1",
		},
		{
			name:  "local action (relative path, no @)",
			input: "./local-action",
			match: false,
		},
		{
			name:  "local action with subdirectory",
			input: "./.github/actions/my-action",
			match: false,
		},
		{
			name:  "docker reference",
			input: "docker://alpine:3.8",
			match: false,
		},
		{
			name:  "docker reference with registry",
			input: "docker://ghcr.io/owner/image:latest",
			match: false,
		},
		{
			name:  "no ref at all",
			input: "actions/checkout",
			match: false,
		},
		{
			name:  "empty string",
			input: "",
			match: false,
		},
		{
			name:  "only @ref, no action path",
			input: "@v3",
			match: false,
		},
		{
			name:       "ref with special characters (release branch)",
			input:      "actions/checkout@releases/v1",
			match:      true,
			actionPath: "actions/checkout",
			ref:        "releases/v1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ghaUsesRegex.FindStringSubmatch(tc.input)
			if tc.match {
				require.NotNil(t, matches, "expected %q to match", tc.input)
				assert.Equal(t, tc.actionPath, matches[1], "action path mismatch")
				assert.Equal(t, tc.ref, matches[2], "ref mismatch")
			} else {
				assert.Nil(t, matches, "expected %q not to match", tc.input)
			}
		})
	}
}

func TestCommitSHARegex(t *testing.T) {
	cases := []struct {
		name  string
		input string
		match bool
	}{
		// SHA-1 (40 hex chars)
		{"valid SHA-1", "8ade135a41bc03ea155e62e844d188df1ea18608", true},
		{"SHA-1 all lowercase", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"SHA-1 uppercase, matched after ToLower", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		// SHA-256 (64 hex chars)
		{"valid SHA-256", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", true},
		{"SHA-256 all zeros", "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"SHA-256 uppercase, matched after ToLower", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2", true},
		// Not a commit SHA
		{"tag", "v3", false},
		{"branch name", "main", false},
		{"short hash (too short for SHA-1)", "abc123", false},
		{"39 chars (one short of SHA-1)", "8ade135a41bc03ea155e62e844d188df1ea1860", false},
		{"41 chars (between SHA-1 and SHA-256)", "8ade135a41bc03ea155e62e844d188df1ea186080", false},
		{"63 chars (one short of SHA-256)", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b", false},
		{"65 chars (one over SHA-256)", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a", false},
		{"non-hex characters", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false},
		{"semver tag", "v4.1.0", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.match, commitSHARegex.MatchString(strings.ToLower(tc.input)))
		})
	}
}

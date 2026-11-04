package agentfiles

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/aitool"
	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// mcpType reports whether p is a file that the agent-config control reads
// the MCP servers of.
func mcpType(t *testing.T, p string) {
	t.Helper()
	typ, ok := Classify(p)
	assert.True(t, ok && (typ == MCPConfig || typ == ClaudeSettings), "Classify(%q) = %q", p, typ)
	_, ok = MCP(p)
	assert.True(t, ok, "MCP(%q)", p)
}

// TestSpecMCPFilesClassify keeps the MCP files of each spec discoverer in
// internal/endpoint/aitool and the files that the control reads in step. A
// new agent spec with a file that the control does not know fails here.
func TestSpecMCPFilesClassify(t *testing.T) {
	home := t.TempDir()
	system, project := aitool.DefaultRegistry().MCPAppFiles(aitool.DiscoveryConfig{HomeDir: home})
	require.NotEmpty(t, system)
	require.NotEmpty(t, project)
	homeFiles := map[string]bool{}
	for _, f := range HomeFiles {
		homeFiles[f] = true
	}
	for _, p := range system {
		rel, err := filepath.Rel(home, p)
		require.NoError(t, err)
		rel = filepath.ToSlash(rel)
		require.False(t, strings.HasPrefix(rel, ".."), "%s is outside the home", p)
		mcpType(t, rel)
		assert.True(t, homeFiles[rel], "HomeFiles lacks %s", rel)
	}
	for _, g := range project {
		mcpType(t, strings.ReplaceAll(filepath.ToSlash(g), "*", "x"))
	}
}

// TestDiscoveredMCPFilesClassify covers the hand-written discoverers. Each
// fixture file holds one server. The discovery must find each one, and the
// control must read each file that the discovery finds a server in.
func TestDiscoveredMCPFilesClassify(t *testing.T) {
	root, err := filepath.Abs("testdata/discovery")
	require.NoError(t, err)
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	found := map[string]bool{}
	err = aitool.DefaultRegistry().Discover(context.Background(), aitool.DiscoveryConfig{HomeDir: home, ProjectDir: project},
		func(it *inventory.Item) error {
			if it.Kind != inventory.KindMCPServer {
				return nil
			}
			// A server of a project in ~/.claude.json names the project
			// folder as its config path.
			if info, err := os.Stat(it.ConfigPath); err != nil || info.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, it.ConfigPath)
			require.NoError(t, err)
			found[filepath.ToSlash(rel)] = true
			return nil
		})
	require.NoError(t, err)
	var fixtures []string
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, relErr := filepath.Rel(root, p)
			fixtures = append(fixtures, filepath.ToSlash(rel))
			return relErr
		}
		return err
	}))
	for _, f := range fixtures {
		assert.True(t, found[f], "the discovery finds no server in %s", f)
	}
	for f := range found {
		_, rel, _ := strings.Cut(f, "/")
		mcpType(t, rel)
	}
}

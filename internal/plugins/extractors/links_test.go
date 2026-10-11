package extractors

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinksFollow(t *testing.T) {
	root := filepath.FromSlash("/r")
	cfg := filepath.Join(root, "cfg")
	var l Links
	var walked []string
	walk := func(name string) func() error {
		return func() error { walked = append(walked, name); return nil }
	}

	require.NoError(t, l.Follow(root, cfg, walk(".claude")))
	require.NoError(t, l.Follow(root, cfg, walk(".vscode")))
	assert.Equal(t, []string{".claude", ".vscode"}, walked, "each name of a folder is walked")

	walked = nil
	require.NoError(t, l.Follow(cfg, root, walk("cfg/.claude")))
	assert.Empty(t, walked, "a link to a folder that holds it is a loop")

	walked = nil
	require.NoError(t, l.Follow(root, cfg, func() error {
		return l.Follow(filepath.Join(root, "other"), cfg, walk("nested"))
	}))
	assert.Empty(t, walked, "a link to a folder that the walk is inside is a loop")
}

func TestLinksBound(t *testing.T) {
	var l Links
	for range MaxLinkedDirs {
		require.NoError(t, l.Follow("/a", "/b", func() error { return nil }))
	}
	assert.ErrorIs(t, l.Follow("/a", "/b", func() error { return nil }), ErrTooManyLinks)
}

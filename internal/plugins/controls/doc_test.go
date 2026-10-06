package controls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/golden"
)

// TestControlsDocIsCurrent keeps the generated blocks of docs/controls.md
// equal to the catalog. make golden rewrites them.
func TestControlsDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "controls.md")
	doc, err := os.ReadFile(path)
	require.NoError(t, err)
	list, err := Catalog()
	require.NoError(t, err)
	got, err := RenderDoc(string(doc), list)
	require.NoError(t, err)
	golden.Assert(t, path, []byte(got))
}

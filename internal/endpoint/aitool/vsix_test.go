package aitool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func TestVSIXReader_ServerDirs(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		eco     model.Ecosystem
		display string
	}{
		{"VS Code Server (WSL, Remote SSH)", ".vscode-server", model.EcosystemVSCode, "VS Code"},
		{"Cursor Server (WSL, Remote SSH)", ".cursor-server", model.EcosystemOpenVSX, "Cursor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			extDir := filepath.Join(home, tt.dir, "extensions")
			require.NoError(t, mkdir(extDir))
			require.NoError(t, os.WriteFile(filepath.Join(extDir, vsixExtensionsFile),
				[]byte(`[{"identifier": {"id": "golang.go"}, "version": "0.50.0"}]`), 0o600))

			manifests, err := newVSIXReader(home).Manifests()
			require.NoError(t, err)
			require.Len(t, manifests, 1)
			assert.Equal(t, tt.eco, manifests[0].Ecosystem)
			assert.Equal(t, []vsixExtension{{ID: "golang.go", Version: "0.50.0"}}, manifests[0].Extensions)
			assert.Equal(t, tt.display, ideNameFromPath(manifests[0].Path))

			eco, ok := ecosystemOfDir(extDir)
			require.True(t, ok)
			assert.Equal(t, tt.eco, eco)
		})
	}
}

package hiddencode_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/hiddencode"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/model"
)

func TestOnlyAFileWithASignIsAManifest(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600))
	}
	write("next.config.js", "module.exports = {}\n")
	write("postcss.config.mjs", "export default config;"+strings.Repeat(" ", 200)+"(function(){"+strings.Repeat("var _0xa1b2=1;", 20)+"})();\n")
	exs := []filesystem.Extractor{hiddencode.New()}
	for _, tc := range []struct {
		path string
		want int
	}{{"next.config.js", 0}, {"postcss.config.mjs", 1}} {
		ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: dir, Path: tc.path}, exs)
		assert.Empty(t, errs, tc.path)
		require.Len(t, ms, tc.want, tc.path)
		if tc.want == 1 {
			assert.Equal(t, model.ManifestKindFile, ms[0].Kind)
			assert.Empty(t, ms[0].Packages)
		}
	}
}

func TestInstallFolders(t *testing.T) {
	e := hiddencode.New()
	for p, want := range map[string]bool{
		"usr/local/lib/node_modules/npm/lib/cli.js": true,
		"node_modules/left-pad/postcss.config.js":   false,
		"client/postcss.config.mjs":                 true,
	} {
		assert.Equal(t, want, e.FileRequired(simplefileapi.New(p, nil)), p)
	}
}

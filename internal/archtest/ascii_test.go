package archtest

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOnlyTUIWritesUnicode fails on a string or a rune literal outside
// internal/tui that holds a character outside ASCII. Only the rich mode of
// the terminal shows a glyph, and it gets the glyph from internal/tui. The
// reports, the plain and agent modes and the pull request comment are
// ASCII, because a middle dot, an arrow, an ellipsis character or an emoji
// is hard to read there.
//
// The test reads the literal as the source writes it. An escape such as
// ​ passes, so a deliberate invisible character stays possible: the
// markdown formats put a zero-width space into untrusted text, so that
// GitHub does not make a link or a mention of it, and the hidden-code check
// lists the characters that it detects.
func TestOnlyTUIWritesUnicode(t *testing.T) {
	root := repoRoot(t)
	for path, src := range sourcesOutside(t, []string{module + "/internal/tui"}) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		require.NoError(t, err)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || (lit.Kind != token.STRING && lit.Kind != token.CHAR) {
				return true
			}
			for _, r := range lit.Value {
				if r < utf8.RuneSelf {
					continue
				}
				rel, err := filepath.Rel(root, path)
				require.NoError(t, err)
				assert.Fail(t, "only internal/tui writes Unicode",
					"%s:%d: the literal holds %q (%U). Write ASCII, or get the rich glyph from internal/tui.",
					filepath.ToSlash(rel), fset.Position(lit.Pos()).Line, r, r)
			}
			return true
		})
	}
}

// asciiGoldens are the directories of the goldens of output that is not
// the rich mode of the terminal: the report formats, the pull request
// comment, the plain and agent modes of the scan view, and vet report
// finding show.
var asciiGoldens = []string{
	"internal/plugins/sinks/testdata",
	"internal/plugins/sinks/prcomment/testdata",
	"internal/view/testdata",
	"internal/cmd/report/testdata",
}

// TestNonRichGoldensAreASCII checks the output itself, behind the check of
// the literals: a glyph can also come from a library or from data. A rich
// golden can hold the glyphs of internal/tui. A JSON Schema of a third
// party is not output of vet.
func TestNonRichGoldensAreASCII(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range asciiGoldens {
		n := 0
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			name := d.Name()
			if strings.Contains(name, "-rich") || strings.HasSuffix(name, ".schema.json") {
				return nil
			}
			n++
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for i, line := range bytes.Split(data, []byte("\n")) {
				if j := bytes.IndexFunc(line, func(r rune) bool { return r >= utf8.RuneSelf }); j >= 0 {
					r, _ := utf8.DecodeRune(line[j:])
					assert.Fail(t, "non-rich output is ASCII", "%s:%d: the golden holds %q (%U)", filepath.ToSlash(rel), i+1, r, r)
				}
			}
			return nil
		})
		require.NoError(t, err)
		assert.NotZero(t, n, "%s holds no golden: update asciiGoldens", dir)
	}
}

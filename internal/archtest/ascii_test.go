package archtest

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// richChrome are the only packages that hold Unicode literals: the marks of
// the rich mode, the spinner frames and the banner art. Each other package
// of internal/tui feeds the reports too, as humanize and escape do.
var richChrome = []string{
	module + "/internal/tui/glyph",
	module + "/internal/tui/progress",
	module + "/internal/tui/banner",
}

// deliberateRunes are the characters outside ASCII that vet writes on
// purpose, with the reason for each.
var deliberateRunes = map[rune]string{
	'\u200b': "a zero-width space stops GitHub from making a link or a mention of untrusted text in markdown",
}

// TestOnlyRichChromeWritesUnicode fails on a string or a rune literal that
// holds a character outside ASCII, outside the packages of the rich chrome.
// Only the rich mode of the terminal shows a glyph, and it gets the glyph
// from internal/tui/glyph. The reports, the plain and agent modes and the
// pull request comment are ASCII, because a middle dot, an arrow, an
// ellipsis character or an emoji is hard to read there.
//
// The test reads the value of the literal, so an escape counts as the
// character that it gives. A literal with a byte escape, such as a byte
// order mark for a detection, holds bytes and not text: the test reads it
// as the source writes it.
func TestOnlyRichChromeWritesUnicode(t *testing.T) {
	root := repoRoot(t)
	for path, src := range sourcesOutside(t, richChrome) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		require.NoError(t, err)
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || (lit.Kind != token.STRING && lit.Kind != token.CHAR) {
				return true
			}
			for _, r := range literalText(t, lit.Value) {
				if r < utf8.RuneSelf || deliberateRunes[r] != "" {
					continue
				}
				assert.Fail(t, "only the rich chrome writes Unicode",
					"%s:%d: the literal holds %q (%U). Write ASCII, or get the rich glyph from internal/tui/glyph.",
					filepath.ToSlash(rel), fset.Position(lit.Pos()).Line, r, r)
			}
			return true
		})
	}
}

// byteEscape matches an escape of one byte, as \xEF or \357.
var byteEscape = regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{3})`)

// literalText is the text of a literal: its value, or the source of a
// literal with a byte escape.
func literalText(t *testing.T, src string) string {
	t.Helper()
	if byteEscape.MatchString(strings.ReplaceAll(src, `\\`, "")) {
		return src
	}
	v, err := strconv.Unquote(src)
	require.NoError(t, err, src)
	return v
}

// embedExcluded are the embedded files that hold detection data outside
// ASCII, with the reason for each. A file that vet writes into a report
// never goes here.
var embedExcluded = map[string]string{}

var goEmbed = regexp.MustCompile(`(?m)^//go:embed (.+)$`)

// TestEmbeddedTextIsASCII fails on an embedded file that holds a character
// outside ASCII. The capability signatures give the descriptions of the
// JSON, JSONL and CycloneDX reports.
func TestEmbeddedTextIsASCII(t *testing.T) {
	root := repoRoot(t)
	n := 0
	for path, src := range sourcesOutside(t, nil) {
		for _, m := range goEmbed.FindAllStringSubmatch(src, -1) {
			for _, pattern := range strings.Fields(m[1]) {
				matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), pattern))
				require.NoError(t, err)
				require.NotEmpty(t, matches, "%s: //go:embed %s matches no file", path, pattern)
				for _, match := range matches {
					err := filepath.WalkDir(match, func(p string, d fs.DirEntry, err error) error {
						if err != nil || d.IsDir() {
							return err
						}
						rel, err := filepath.Rel(root, p)
						if err != nil {
							return err
						}
						rel = filepath.ToSlash(rel)
						if embedExcluded[rel] != "" {
							return nil
						}
						n++
						return assertASCII(t, p, rel, "embedded text is ASCII")
					})
					require.NoError(t, err)
				}
			}
		}
	}
	assert.NotZero(t, n, "the test found no embedded file")
}

// assertASCII fails on each line of a file that holds a character outside
// ASCII, and names the line and the character.
func assertASCII(t *testing.T, path, rel, msg string) error {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for i, line := range bytes.Split(data, []byte("\n")) {
		if j := bytes.IndexFunc(line, func(r rune) bool { return r >= utf8.RuneSelf }); j >= 0 {
			r, _ := utf8.DecodeRune(line[j:])
			assert.Fail(t, msg, "%s:%d: the file holds %q (%U)", rel, i+1, r, r)
		}
	}
	return nil
}

// glyphAllowed are the only packages that import internal/tui/glyph. A
// report format writes ASCII text and takes no rich glyph.
var glyphAllowed = []string{
	module + "/internal/tui",
	module + "/internal/view",
}

func TestOnlyTheViewAndTheTUIImportGlyphs(t *testing.T) {
	for _, p := range listPackages(t) {
		if underAny(p.path, glyphAllowed) {
			continue
		}
		assert.NotContains(t, p.imports, module+"/internal/tui/glyph", "package %s imports internal/tui/glyph", p.path)
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
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			return assertASCII(t, path, filepath.ToSlash(rel), "non-rich output is ASCII")
		})
		require.NoError(t, err)
		assert.NotZero(t, n, "%s holds no golden: update asciiGoldens", dir)
	}
}

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
	"slices"
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
// character that it gives. A byte escape, such as the bytes of a byte order
// mark for a detection, gives a byte and not a character, so it passes.
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
			for _, r := range literalRunes(t, lit.Value) {
				if deliberateRunes[r] != "" {
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

// literalRunes returns the characters outside ASCII that a Go literal
// gives. A byte escape, as \xEF or \357, gives a byte and no character.
func literalRunes(t *testing.T, src string) []rune {
	t.Helper()
	var out []rune
	if strings.HasPrefix(src, "`") {
		for _, r := range src {
			if r >= utf8.RuneSelf {
				out = append(out, r)
			}
		}
		return out
	}
	quote, body := src[0], src[1:len(src)-1]
	for body != "" {
		r, multibyte, tail, err := strconv.UnquoteChar(body, quote)
		require.NoError(t, err, src)
		if multibyte {
			out = append(out, r)
		}
		body = tail
	}
	return out
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

// globalModeTUI are the internal/tui packages that draw for the messaging
// mode, which stderr decides. A report format draws for the mode of its
// destination with internal/tui/page.
var globalModeTUI = []string{
	module + "/internal/tui/style",
	module + "/internal/tui/section",
	module + "/internal/tui/stat",
}

func TestReportFormatsDrawForTheirDestination(t *testing.T) {
	for _, p := range listPackages(t) {
		if !under(p.path, module+"/internal/plugins/sinks") {
			continue
		}
		for _, imp := range p.imports {
			assert.False(t, slices.Contains(globalModeTUI, imp), "package %s imports %s: draw with internal/tui/page", p.path, imp)
		}
	}
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

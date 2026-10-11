// Package evasion holds the evasion corpus: synthetic cases that copy the
// shape of a published attack, and the shapes that an attacker can change
// to get past a detection. A test scans each case with the built-in
// extractors and controls, and writes coverage.md. See README.md.
package evasion

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/rogpeppe/go-internal/txtar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/hiddentext"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/test/internal/scantest"
)

// evasionCase is one case of the corpus.
type evasionCase struct {
	group, name string
	summary     string
	want        []string
	// miss is why the detections do not catch the case yet. It is empty
	// for a case that they must catch.
	miss string
	// have is what the scan gives for a known miss today. The test checks
	// it, so a known miss cannot lose a finding that it had.
	have []string
	// source is "endpoint" for a case that vet endpoint audit reads, with
	// the files under the home folder. It is empty for a directory scan.
	source string
	files  []txtar.File
}

// none is the want of a case that must give no finding.
const none = "none"

const sourceEndpoint = "endpoint"

// parseCase reads a case. A Windows checkout can turn each line end into
// CRLF, which would change the bytes of the case, so the line ends become
// LF. A case writes a CR with {% "\r" %}.
func parseCase(group, name string, data []byte) (evasionCase, error) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if !utf8.Valid(data) {
		return evasionCase{}, fmt.Errorf("%s/%s: the case is not valid UTF-8: write each raw byte as an escape, such as {%% \"\\xff\" %%}", group, name)
	}
	if i := bytes.IndexFunc(data, unseen); i >= 0 {
		return evasionCase{}, fmt.Errorf("%s/%s: byte %d is a character that a reader cannot see: write it as an escape, such as {%% \"\\u200b\" %%}", group, name, i)
	}
	a := txtar.Parse(data)
	c := evasionCase{group: group, name: name, files: a.Files}
	hasWant, hasHave := false, false
	for _, line := range strings.Split(string(a.Comment), "\n") {
		key, value, ok := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		if ok && (key == "want" || key == "have") && value == "" {
			return c, fmt.Errorf("%s/%s: the %s line is empty: write the control ids, or none", group, name, key)
		}
		switch {
		case ok && key == "want":
			c.want, hasWant = idList(value), true
		case ok && key == "have":
			c.have, hasHave = idList(value), true
		case ok && key == "miss":
			c.miss = value
		case ok && key == "source":
			c.source = value
		case strings.HasPrefix(line, "# "):
			if c.summary == "" {
				c.summary = strings.TrimPrefix(line, "# ")
			}
		case strings.TrimSpace(line) != "":
			return c, fmt.Errorf("%s/%s: unknown line %q", group, name, line)
		}
	}
	switch {
	case c.summary == "":
		return c, fmt.Errorf("%s/%s: the case has no summary line", group, name)
	case !hasWant:
		return c, fmt.Errorf("%s/%s: the case has no want line", group, name)
	case len(c.files) == 0:
		return c, fmt.Errorf("%s/%s: the case has no file", group, name)
	case c.source != "" && c.source != sourceEndpoint:
		return c, fmt.Errorf("%s/%s: unknown source %q", group, name, c.source)
	case c.miss != "" && !hasHave:
		return c, fmt.Errorf("%s/%s: a known miss needs a have line with what the scan gives today", group, name)
	case c.miss == "" && hasHave:
		return c, fmt.Errorf("%s/%s: only a known miss has a have line", group, name)
	}
	for _, f := range c.files {
		if !filepath.IsLocal(filepath.FromSlash(f.Name)) {
			return c, fmt.Errorf("%s/%s: the file %q is not inside the case", group, name, f.Name)
		}
	}
	return c, nil
}

// idList reads a list of control ids, or none.
func idList(value string) []string {
	v := strings.Fields(value)
	if slices.Equal(v, []string{none}) {
		return nil
	}
	slices.Sort(v)
	return v
}

func loadCases(t *testing.T) []evasionCase {
	t.Helper()
	var out []evasionCase
	err := filepath.WalkDir("cases", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".txtar" {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		c, err := parseCase(filepath.Base(filepath.Dir(p)), strings.TrimSuffix(filepath.Base(p), ".txtar"), data)
		if err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, out)
	return out
}

// unseen reports a character that shows as nothing or changes the text
// next to it. A reviewer cannot see it in a case file.
func unseen(r rune) bool {
	if r < utf8.RuneSelf {
		return (r < ' ' && r != '\t' && r != '\n') || r == 0x7F
	}
	switch r {
	case 0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0:
		return true
	}
	return unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Mn, unicode.Me, unicode.Co) || !unicode.IsGraphic(r)
}

// loader is a synthetic obfuscated loader with the tokens of a real one. It
// runs no dynamic code, so it cannot act.
var loader = "(function(){var _0xa1b2=function(){return 1};" + strings.Repeat("var _0xc3d4=_0xa1b2();", 10) + "})();"

// dynamicLoader does what a real loader must do to act: it puts require on
// the global object and builds a function from a decoded string. Its
// payload is console.log(1).
var dynamicLoader = "global['r']=require;(function(){var _0xa1b2=Function(atob('Y29uc29sZS5sb2coMSk='));" + strings.Repeat("var _0xc3d4=_0xa1b2;", 8) + "_0xa1b2();})();"

// funcs write the bytes that a reader cannot see or type in a case file.
var funcs = template.FuncMap{
	"repeat":        strings.Repeat,
	"chars":         func(s string) []string { return strings.Split(s, "") },
	"loader":        func() string { return loader },
	"dynamicloader": func() string { return dynamicLoader },
	"selectors":     hiddentext.Selectors,
	"tags":          hiddentext.Tags,
}

// expand writes the files of a case under dir. A file body is a template
// with the delimiters {% and %}. A Go string constant in it can hold any
// escape, such as {% "\u00a0" %}.
func expand(dir string, files []txtar.File) error {
	for _, f := range files {
		tmpl, err := template.New(f.Name).Delims("{%", "%}").Funcs(funcs).Parse(string(f.Data))
		if err != nil {
			return err
		}
		var b bytes.Buffer
		if err := tmpl.Execute(&b, nil); err != nil {
			return err
		}
		p := filepath.Join(dir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// source returns the source of a case whose files are under dir.
func source(t *testing.T, c evasionCase, dir string) plugin.Source {
	t.Helper()
	if c.source == sourceEndpoint {
		return scantest.Endpoint(dir)
	}
	return scantest.Directory(t, dir)
}

// TestEvasionCorpus scans each case. A case with no miss line must give
// exactly the findings of its want line. A known miss does not fail the
// test, but a known miss that the detections now catch does, so that its
// author removes the miss line. coverage.md records the result.
func TestEvasionCorpus(t *testing.T) {
	if !withCGO {
		t.Skip("the dynamic-code cases need a vet built with CGO")
	}
	attacks, err := controls.AttackIDs()
	require.NoError(t, err)
	cases := loadCases(t)
	var table bytes.Buffer
	table.WriteString("# Evasion corpus coverage\n\n" +
		"`go test ./test/evasion/` writes this file. Run it with `UPDATE_GOLDEN=1` after you change a case or a\n" +
		"detection, and commit the diff. See README.md.\n\n")
	passes, fails, misses := 0, 0, 0
	group := ""
	for _, c := range cases {
		dir := t.TempDir()
		require.NoError(t, expand(dir, c.files), "%s/%s", c.group, c.name)
		got := scantest.ControlIDs(scantest.Scan(t, source(t, c, dir)))
		caught := slices.Equal(got, c.want)
		t.Run(c.group+"/"+c.name, func(t *testing.T) {
			if c.miss == "" {
				assert.Equal(t, c.want, got, c.summary)
				return
			}
			if caught {
				assert.Fail(t, "the detections now catch this known miss: remove its miss and have lines")
				return
			}
			assert.Equal(t, c.have, got, "the findings of this known miss changed: fix the regression, or update its have line")
		})
		if c.group != group {
			if group != "" {
				table.WriteString("\n")
			}
			group = c.group
			fmt.Fprintf(&table, "## %s\n\n| Case | Expected | Actual | Gate | Result |\n| --- | --- | --- | --- | --- |\n", group)
		}
		result := "pass"
		switch {
		case c.miss != "":
			result = "miss: " + c.miss
			misses++
		case !caught:
			result = "fail"
			fails++
		default:
			passes++
		}
		gate := "passes"
		if slices.ContainsFunc(got, func(id string) bool { return slices.Contains(attacks, id) }) {
			gate = "fails"
		}
		fmt.Fprintf(&table, "| `%s`: %s | %s | %s | %s | %s |\n", c.name, cell(c.summary), ids(c.want), ids(got), gate, cell(result))
	}
	fmt.Fprintf(&table, "\nTotal: %d cases, %d pass, %d fail, %d known misses.\n", passes+fails+misses, passes, fails, misses)
	golden.Assert(t, "coverage.md", table.Bytes())
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func ids(v []string) string {
	if len(v) == 0 {
		return none
	}
	return "`" + strings.Join(v, "`, `") + "`"
}

func TestParseCase(t *testing.T) {
	head := "# s\nwant: none\n"
	cases := []struct {
		name, data, err string
	}{
		{"nul", head + "-- a.js --\na\x00b\n", "cannot see"},
		{"escape", head + "-- a.js --\na\x1bb\n", "cannot see"},
		{"lone carriage return", head + "-- a.js --\na\rb\n", "cannot see"},
		{"zero-width space", head + "-- a.js --\na\u200bb\n", "cannot see"},
		{"invalid UTF-8", head + "-- a.js --\na\xffb\n", "not valid UTF-8"},
		{"path outside the case", head + "-- ../a.js --\nx\n", "not inside the case"},
		{"absolute path", head + "-- /tmp/a.js --\nx\n", "not inside the case"},
		{"miss with no have line", head + "miss: r\n-- a.js --\nx\n", "needs a have line"},
		{"empty want line", "# s\nwant:\n-- a.js --\nx\n", "want line is empty"},
		{"have line with no miss", head + "have: none\n-- a.js --\nx\n", "only a known miss"},
		{"crlf line ends", head + "-- a.js --\r\na\r\n", ""},
		{"tab", head + "-- a.js --\na\tb\n", ""},
		{"visible letters", head + "-- a.js --\nשלום\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCase("g", "c", []byte(tc.data))
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

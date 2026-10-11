// Package evasion holds the evasion corpus: synthetic cases that copy the
// shape of a published attack, and the shapes that an attacker can change
// to get past a detection. A test scans each case with the built-in
// extractors and controls, and writes coverage.md. See README.md.
package evasion

import (
	"bytes"
	"context"
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

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/plugins/sources/endpoint"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// evasionCase is one case of the corpus.
type evasionCase struct {
	group, name string
	summary     string
	want        []string
	// miss is why the detections do not catch the case yet. It is empty
	// for a case that they must catch.
	miss string
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
	if i := bytes.IndexFunc(data, unseen); i >= 0 {
		return evasionCase{}, fmt.Errorf("%s/%s: byte %d is a character that a reader cannot see: write it as an escape, such as {%% \"\\u200b\" %%}", group, name, i)
	}
	a := txtar.Parse(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	c := evasionCase{group: group, name: name, files: a.Files}
	for _, line := range strings.Split(string(a.Comment), "\n") {
		key, value, ok := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch {
		case ok && key == "want":
			c.want = strings.Fields(value)
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
	case len(c.want) == 0:
		return c, fmt.Errorf("%s/%s: the case has no want line", group, name)
	case len(c.files) == 0:
		return c, fmt.Errorf("%s/%s: the case has no file", group, name)
	case c.source != "" && c.source != sourceEndpoint:
		return c, fmt.Errorf("%s/%s: unknown source %q", group, name, c.source)
	}
	if slices.Equal(c.want, []string{none}) {
		c.want = nil
	}
	slices.Sort(c.want)
	return c, nil
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
		return false
	}
	switch r {
	case 0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0:
		return true
	}
	return unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Mn, unicode.Me, unicode.Co) || !unicode.IsGraphic(r)
}

// loader is a synthetic obfuscated loader with the tokens of a real one. It
// runs nothing.
var loader = "(function(){var _0xa1b2=function(){return 1};" + strings.Repeat("var _0xc3d4=_0xa1b2();", 10) + "})();"

// funcs write the bytes that a reader cannot see or type in a case file.
var funcs = template.FuncMap{
	"repeat": strings.Repeat,
	"chars":  func(s string) []string { return strings.Split(s, "") },
	"loader": func() string { return loader },
	// selectors hides text in variation selectors, one byte in each, as
	// GlassWorm does.
	"selectors": func(s string) string {
		var b strings.Builder
		for _, c := range []byte(s) {
			if c < 16 {
				b.WriteRune(0xFE00 + rune(c))
			} else {
				b.WriteRune(0xE0100 + rune(c) - 16)
			}
		}
		return b.String()
	},
	// tags spells ASCII text in Unicode tag characters.
	"tags": func(s string) string {
		var b strings.Builder
		for _, c := range s {
			b.WriteRune(0xE0000 + c)
		}
		return b.String()
	},
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

type allEnabled struct{}

func (allEnabled) PluginEnabled(string, bool) bool     { return true }
func (allEnabled) PluginOrigin(string, string) string  { return "" }
func (allEnabled) PluginOptions(string) map[string]any { return map[string]any{} }

// source returns the source of a case whose files are under dir.
func source(t *testing.T, c evasionCase, dir string) plugin.Source {
	t.Helper()
	if c.source == sourceEndpoint {
		return endpoint.New(endpoint.Options{}, endpoint.System{
			Hostname: func() (string, error) { return "evasion", nil },
			Home:     func() (string, error) { return dir, nil },
			Scanners: func() ([]inventory.Scanner, error) { return nil, nil },
		})
	}
	src, err := sources.New(dir, sources.Options{})
	require.NoError(t, err)
	return src
}

// scan runs the extractors and the controls of a default scan on src, with
// no enricher, and returns the sorted control ids of the findings.
func scan(t *testing.T, src plugin.Source) []string {
	t.Helper()
	ctx := context.Background()
	built, err := controls.Build(allEnabled{})
	require.NoError(t, err)
	cs := make([]engine.Control, 0, len(built))
	for _, c := range built {
		cs = append(cs, engine.Control{ID: c.Name, Plugin: c.Plugin})
	}
	store, err := state.Open(ctx, state.Options{StateDir: t.TempDir()})
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	res, err := engine.Run(ctx, engine.Options{
		Store: store, Source: src, Controls: cs,
		Extractors:  func(plugin.ArtifactKind) ([]plugin.Extractor, error) { return extractors.For(model.PackagesDeclared) },
		OptionsHash: "evasion", VetVersion: "test", BatchSize: 10,
	})
	require.NoError(t, err)
	defer func() { assert.NoError(t, res.Scan.Close()) }()
	var ids []string
	for f, err := range res.Scan.Findings(ctx, plugin.FindingQuery{}) {
		require.NoError(t, err)
		if !slices.Contains(ids, f.ControlID) {
			ids = append(ids, f.ControlID)
		}
	}
	slices.Sort(ids)
	return ids
}

// TestEvasionCorpus scans each case. A case with no miss line must give
// exactly the findings of its want line. A known miss does not fail the
// test, but a known miss that the detections now catch does, so that its
// author removes the miss line. coverage.md records the result.
func TestEvasionCorpus(t *testing.T) {
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
		got := scan(t, source(t, c, dir))
		caught := slices.Equal(got, c.want)
		t.Run(c.group+"/"+c.name, func(t *testing.T) {
			if c.miss == "" {
				assert.Equal(t, c.want, got, c.summary)
				return
			}
			assert.False(t, caught, "the detections now catch this known miss: remove its miss line")
		})
		if c.group != group {
			if group != "" {
				table.WriteString("\n")
			}
			group = c.group
			fmt.Fprintf(&table, "## %s\n\n| Case | Expected | Actual | Result |\n| --- | --- | --- | --- |\n", group)
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
		fmt.Fprintf(&table, "| `%s`: %s | %s | %s | %s |\n", c.name, cell(c.summary), ids(c.want), ids(got), cell(result))
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

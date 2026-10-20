// Package reach holds the reach corpus. It runs the call graph search of
// the codeusage enricher on small synthetic projects with their dependency
// code, and checks each answer against the truth of the case. It writes the
// result to coverage.md. See README.md.
package reach

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/txtar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/model"
)

// The truths of a target.
const (
	truthCalled    = "called"
	truthNotCalled = "not-called"
)

// The answers of the search, as the coverage table writes them.
const (
	answerFound    = "found"
	answerNotFound = "not-found"
	answerUnproved = "unproved"
	// answerWeak is a path with a call that the graph only guesses. The
	// engine keeps such a finding imported, so it is no claim.
	answerWeak      = "weak path"
	answerNoAnswer  = "no-answer"
	statusFoundName = "found"
)

type target struct {
	truth, name string
}

type reachCase struct {
	group, name, summary, language string
	units                          []codeusage.Unit
	targets                        []target
	entrypoints                    []string
	// miss names why the search does not find a call yet, with the issue
	// that fixes it. A known miss is not a false negative, because the
	// answer is unproved, never not-found.
	miss  string
	files []txtar.File
}

// parseCase reads a case. The comment holds a summary line, the language,
// a unit line for each dependency, a called or not-called line for each
// target, and optional entrypoint lines.
func parseCase(group, name string, data []byte) (reachCase, error) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	a := txtar.Parse(data)
	c := reachCase{group: group, name: name, files: a.Files}
	for _, line := range strings.Split(string(a.Comment), "\n") {
		key, value, ok := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(line, "# "):
			if c.summary == "" {
				c.summary = strings.TrimPrefix(line, "# ")
			}
		case ok && key == "lang":
			c.language = value
		case ok && key == "unit":
			unitKey, dir, ok := strings.Cut(value, " ")
			if !ok {
				return c, fmt.Errorf("%s/%s: a unit line is \"unit: <key> <dir>\"", group, name)
			}
			c.units = append(c.units, codeusage.Unit{Key: unitKey, Dir: strings.TrimSpace(dir)})
		case ok && (key == truthCalled || key == truthNotCalled):
			c.targets = append(c.targets, target{truth: key, name: value})
		case ok && key == "entrypoint":
			c.entrypoints = append(c.entrypoints, value)
		case ok && key == "miss":
			c.miss = value
		case strings.TrimSpace(line) != "":
			return c, fmt.Errorf("%s/%s: unknown line %q", group, name, line)
		}
	}
	switch {
	case c.summary == "":
		return c, fmt.Errorf("%s/%s: the case has no summary line", group, name)
	case c.language != "go" && c.language != "rust":
		return c, fmt.Errorf("%s/%s: lang is go or rust", group, name)
	case len(c.targets) == 0:
		return c, fmt.Errorf("%s/%s: the case has no called or not-called line", group, name)
	}
	for _, f := range c.files {
		if !filepath.IsLocal(filepath.FromSlash(f.Name)) {
			return c, fmt.Errorf("%s/%s: the file %q is not inside the case", group, name, f.Name)
		}
	}
	return c, nil
}

func readCases(t *testing.T) []reachCase {
	t.Helper()
	var cases []reachCase
	for _, group := range []string{"go", "rust"} {
		entries, err := os.ReadDir(filepath.Join("cases", group))
		require.NoError(t, err)
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".txtar") {
				continue
			}
			data, err := os.ReadFile(filepath.Join("cases", group, e.Name()))
			require.NoError(t, err)
			c, err := parseCase(group, strings.TrimSuffix(e.Name(), ".txtar"), data)
			require.NoError(t, err)
			cases = append(cases, c)
		}
	}
	return cases
}

// row is the result for one target of a case.
type row struct {
	c      reachCase
	t      target
	answer string
}

// ecosystems maps the language of a case to the ecosystem of its packages.
var ecosystems = map[string]model.Ecosystem{"go": model.EcosystemGo, "rust": model.EcosystemCargo}

// ok reports an answer that keeps the release bar: a found target is
// called, and a not-found target is not called. An unproved answer is
// always safe, but a case with no miss line must give the truth. A known
// miss that gives no path is a false negative. It keeps the bar only in a
// language where vet does not say not-called.
func (r row) ok() bool {
	switch {
	case r.answer == answerFound:
		return r.t.truth == truthCalled
	case r.answer == answerNotFound && r.t.truth == truthNotCalled:
		return true
	case r.answer == answerNotFound:
		return r.c.miss != "" && !engine.ProvesNotCalled(ecosystems[r.c.language])
	}
	return r.c.miss != ""
}

func run(t *testing.T, c reachCase) []row {
	t.Helper()
	dir := t.TempDir()
	for _, f := range c.files {
		path := filepath.Join(dir, filepath.FromSlash(f.Name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, f.Data, 0o600))
	}
	q := codeusage.ReachQuery{Sources: c.entrypoints}
	for _, u := range c.units {
		q.Units = append(q.Units, codeusage.Unit{Key: u.Key, Dir: filepath.Join(dir, filepath.FromSlash(u.Dir))})
	}
	keys := make([]string, len(c.targets))
	for i, tg := range c.targets {
		keys[i] = codeusage.SymbolKey(c.language, tg.name)
		require.NotEmpty(t, keys[i], "%s has no symbol key", tg.name)
		q.Targets = append(q.Targets, keys[i])
	}
	res, err := codeusage.Search(context.Background(), dir, q)
	require.NoError(t, err)
	rows := make([]row, len(c.targets))
	for i, tg := range c.targets {
		a, found := res.Answers[keys[i]]
		answer := answerNoAnswer
		switch {
		case !found:
		case a.Status == statusFoundName && slices.ContainsFunc(a.Path, func(h model.PathHop) bool { return h.Confidence != "" && h.Confidence != "high" }):
			answer = answerWeak
		case a.Status == statusFoundName:
			answer = answerFound
		case a.Status == answerNotFound && !a.RootFallback:
			answer = answerNotFound
		default:
			answer = answerUnproved
		}
		rows[i] = row{c: c, t: tg, answer: answer}
	}
	return rows
}

// TestReachCorpus checks the release bar of reach: the precision of a
// found path is 100%, and no target that the code calls comes back with
// no path. It writes coverage.md.
func TestReachCorpus(t *testing.T) {
	if !codeusage.Available() {
		t.Skip("the reach corpus needs a vet built with CGO")
	}
	var rows []row
	for _, c := range readCases(t) {
		t.Run(c.group+"/"+c.name, func(t *testing.T) {
			got := run(t, c)
			for _, r := range got {
				assert.True(t, r.ok(), "%s: %s is %s, the search says %s", c.summary, r.t.name, r.t.truth, r.answer)
			}
			rows = append(rows, got...)
		})
	}
	golden.Assert(t, "coverage.md", coverage(rows))
}

// coverage writes the table of each target and the numbers of each
// language.
func coverage(rows []row) []byte {
	var b strings.Builder
	b.WriteString("# Reach corpus coverage\n\nThis file is generated by `TestReachCorpus`. Do not edit it. See [README.md](README.md).\n\n")
	b.WriteString("| Language | Called targets | Found | Unproved | Not-called targets | Not found | Unproved | Precision of found | False negatives of not found | vet says not-called |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n")
	for _, lang := range []string{"go", "rust"} {
		var called, found, calledUnproved, notCalled, notFound, notCalledUnproved, falseFound, falseNotFound int
		for _, r := range rows {
			if r.c.language != lang {
				continue
			}
			switch r.t.truth {
			case truthCalled:
				called++
				switch r.answer {
				case answerFound:
					found++
				case answerNotFound:
					falseNotFound++
				default:
					calledUnproved++
				}
			case truthNotCalled:
				notCalled++
				switch r.answer {
				case answerNotFound:
					notFound++
				case answerFound:
					falseFound++
				default:
					notCalledUnproved++
				}
			}
		}
		says := "no"
		if engine.ProvesNotCalled(ecosystems[lang]) {
			says = "yes"
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %s | %s | %s |\n", lang, called, found, calledUnproved, notCalled, notFound,
			notCalledUnproved, percent(found, found+falseFound), percent(falseNotFound, notFound+falseNotFound), says)
	}
	b.WriteString("\n| Case | Summary | Target | Truth | Search | Miss |\n| --- | --- | --- | --- | --- | --- |\n")
	slices.SortStableFunc(rows, func(x, y row) int {
		return strings.Compare(x.c.group+"/"+x.c.name, y.c.group+"/"+y.c.name)
	})
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s/%s | %s | `%s` | %s | %s | %s |\n", r.c.group, r.c.name, r.c.summary, r.t.name, r.t.truth, r.answer, r.c.miss)
	}
	return []byte(b.String())
}

func percent(n, of int) string {
	if of == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(of))
}

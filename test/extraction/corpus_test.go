// Package extraction holds the golden extraction corpus: the fixtures of
// the Scalibr research, each with the manifests that the default extractor
// set returns. A change in an extractor, or in Scalibr, shows as a golden
// diff in review. UPDATE_GOLDEN=1 rewrites the files.
package extraction

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/model"
)

type corpusCase struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	File  string `json:"file"`
}

type manifestView struct {
	Extractor string   `json:"extractor"`
	Kind      string   `json:"kind"`
	Ecosystem string   `json:"ecosystem"`
	Packages  []string `json:"packages"`
	Edges     []string `json:"edges,omitempty"`
}

type caseView struct {
	Manifests []manifestView `json:"manifests"`
	Errors    []string       `json:"errors,omitempty"`
}

// packageLine is one package with its flags: "+" direct, "d" dev, and the
// line when the extractor knows it.
func packageLine(p *model.Package) string {
	flags := ""
	if p.Direct {
		flags += "+"
	}
	if p.Dev {
		flags += "d"
	}
	s := p.ID.String()
	if flags != "" {
		s += " [" + flags + "]"
	}
	if p.Line > 0 {
		s += fmt.Sprintf(" :%d", p.Line)
	}
	return s
}

func view(ms []*model.Manifest, errs []error, root string) caseView {
	v := caseView{Manifests: []manifestView{}}
	for _, m := range ms {
		mv := manifestView{Extractor: m.Extractor, Kind: string(m.Kind), Ecosystem: string(m.Ecosystem), Packages: []string{}}
		for _, p := range m.Packages {
			mv.Packages = append(mv.Packages, packageLine(p))
		}
		if m.Graph != nil {
			m.Graph.Edges(func(p, c model.PackageVersion) { mv.Edges = append(mv.Edges, p.String()+" -> "+c.String()) })
			sort.Strings(mv.Edges)
		}
		v.Manifests = append(v.Manifests, mv)
	}
	sort.Slice(v.Manifests, func(i, j int) bool { return v.Manifests[i].Extractor < v.Manifests[j].Extractor })
	for _, err := range errs {
		v.Errors = append(v.Errors, strings.ReplaceAll(err.Error(), root, "$ROOT"))
	}
	sort.Strings(v.Errors)
	return v
}

func TestCorpus(t *testing.T) {
	b, err := os.ReadFile("corpus.json")
	require.NoError(t, err)
	var cases []corpusCase
	require.NoError(t, json.Unmarshal(b, &cases))
	require.NotEmpty(t, cases)

	exs, err := extractors.Default()
	require.NoError(t, err)

	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("corpus", c.ID))
			require.NoError(t, err)
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: root, Path: filepath.ToSlash(c.File)}, exs)
			golden.AssertJSON(t, filepath.Join("golden", c.ID+".json"), view(ms, errs, root))
			assertPURLRoundTrip(t, ms)
		})
	}
}

// assertPURLRoundTrip checks that the PURL of each package parses back to
// the same package key, so a PURL in a report or a policy names the same
// package as the scan.
func assertPURLRoundTrip(t *testing.T, ms []*model.Manifest) {
	t.Helper()
	for _, m := range ms {
		for _, p := range m.Packages {
			purl := p.ID.PURL()
			require.NotEmpty(t, purl, p.ID.String())
			back, err := model.ParsePURL(purl)
			require.NoError(t, err, purl)
			assert.Equal(t, p.ID.Key(), back.Key(), purl)
		}
	}
}

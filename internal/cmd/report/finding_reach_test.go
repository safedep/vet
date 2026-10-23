package report

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

func TestFindingShowReach(t *testing.T) {
	record := &finding.ReachSymbols{Record: "GO-2026-0001", Coverage: "exact", Review: "verified", Source: "vuln-symbols", License: "CC-BY-4.0"}
	scan := &report.ReachInfo{Level: report.ReachFunction, Status: report.ReachComputed, Roots: &report.ReachRoots{Total: 4}}
	cases := map[string]*finding.Reach{
		"called": {
			Level: finding.ReachCalled, Confidence: finding.ConfidenceMedium, FixSites: []string{"golang.org/x/net/html.Tokenizer.Next"}, Symbols: record,
			Imports: []model.ImportSite{{File: "main.go", Line: 3}},
			Path: []model.PathHop{
				{Function: "cmd/app/main.go//serve", Root: "query"},
				{Function: "golang.org//x//net//html//Parse", File: "cmd/app/main.go", Line: 12, Edge: "direct", Confidence: "high"},
				{Function: "golang.org//x//net//html//Tokenizer//Next", File: "html/parse.go", Line: 88, Edge: "cha", Confidence: "medium"},
			},
		},
		"not-called":     {Level: finding.ReachNotCalled, Confidence: finding.ConfidenceMedium, FixSites: []string{"golang.org/x/net/html.Render"}, Symbols: record},
		"no-entry-point": {Level: finding.ReachImported, Cause: finding.ReachNoEntryPoint, Confidence: finding.ConfidenceHigh, Symbols: record},
		"transitive":     {Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceMedium, Via: []string{"pkg:golang/a@v1.0.0", "pkg:golang/b@v1.0.0"}},
		"unknown":        {Level: finding.ReachUnknown, Cause: finding.ReachBudget, Confidence: finding.ConfidenceLow},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			var b strings.Builder
			reachRows(r, scan, func(k, v string) {
				if v != "" {
					b.WriteString(k + ": " + v + "\n")
				}
			})
			golden.Assert(t, filepath.Join("testdata", "finding-reach-"+name+".golden"), []byte(b.String()))
		})
	}
}

//go:build falsepositive

// Package falsepositive scans clean projects at fixed commits and fails on
// each attack finding. It needs the network, so it runs on its own build
// tag, not in go test ./... See README.md.
package falsepositive

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/test/internal/scantest"
)

type repo struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Commit string `yaml:"commit"`
	Why    string `yaml:"why"`
}

// checkout fetches one commit of a repository into dir, with no history.
// VET_FP_CACHE keeps the checkouts between runs.
func checkout(t *testing.T, r repo) string {
	t.Helper()
	root := os.Getenv("VET_FP_CACHE")
	if root == "" {
		root = t.TempDir()
	}
	dir := filepath.Join(root, r.Name+"-"+r.Commit[:12])
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return dir
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for _, args := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--depth", "1", r.URL, r.Commit},
		{"-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)
	}
	return dir
}

// TestFalsePositives scans each clean project. An attack finding fails the
// test. The other findings of the hidden-code and agent-config families go
// to the table, so a reviewer sees the noise of a control that warns.
// VET_FP_REPORT names a file for the table.
func TestFalsePositives(t *testing.T) {
	data, err := os.ReadFile("repos.yaml")
	require.NoError(t, err)
	var repos []repo
	require.NoError(t, yaml.Unmarshal(data, &repos))
	attacks, err := controls.AttackIDs()
	require.NoError(t, err)

	var table strings.Builder
	table.WriteString("| Project | Attack findings | Other findings |\n| --- | --- | --- |\n")
	for _, r := range repos {
		t.Run(r.Name, func(t *testing.T) {
			fs := scantest.Scan(t, scantest.Directory(t, checkout(t, r)))
			var attack, other []string
			for _, f := range fs {
				if f.Family != finding.FamilyHiddenCode && f.Family != finding.FamilyAgentConfig {
					continue
				}
				line := fmt.Sprintf("`%s` %s", f.ControlID, f.Path())
				if slices.Contains(attacks, f.ControlID) {
					attack = append(attack, line)
					assert.Failf(t, "an attack finding on a clean project", "%s: %s", line, f.Title)
					continue
				}
				other = append(other, line)
			}
			fmt.Fprintf(&table, "| %s | %s | %s |\n", r.Name, cell(attack), cell(other))
		})
	}
	t.Log("\n" + table.String())
	if p := os.Getenv("VET_FP_REPORT"); p != "" {
		require.NoError(t, os.WriteFile(p, []byte(table.String()), 0o644))
	}
}

func cell(lines []string) string {
	if len(lines) == 0 {
		return "none"
	}
	return strings.Join(lines, "<br>")
}

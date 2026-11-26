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
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/test/internal/scantest"
)

type repo struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Commit string `yaml:"commit"`
	Why    string `yaml:"why"`
}

// checkout fetches one commit of a repository into dir, with depth commits
// of history. A pull request scan needs depth 2 for the first parent.
// VET_FP_CACHE keeps the checkouts between runs.
func checkout(t *testing.T, r repo, depth int) string {
	t.Helper()
	root := os.Getenv("VET_FP_CACHE")
	if root == "" {
		root = t.TempDir()
	}
	dir := filepath.Join(root, fmt.Sprintf("%s-%s-%d", r.Name, r.Commit[:12], depth))
	// A failed clone leaves a .git folder with no checkout, and a local edit
	// changes what the scan reads. So a cached folder counts only when its
	// HEAD is the pinned commit and its tree is clean.
	head, headErr := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	status, statusErr := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=all", "--ignored").Output()
	if headErr == nil && statusErr == nil && strings.TrimSpace(string(head)) == r.Commit && len(status) == 0 {
		return dir
	}
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for _, args := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--depth", strconv.Itoa(depth), r.URL, r.Commit},
		{"-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)
	}
	return dir
}

// TestFalsePositives scans each clean project of repos.yaml, and each clean
// commit of changes.yaml against its first parent, as a pull request scan
// does. An attack finding fails the test. The other findings of the
// hidden-code and agent-config families go to the tables, so a reviewer sees
// the noise of a control that warns. The tables leave out the other
// families, such as the vulnerabilities of a project, because they are not
// detections of hidden code. VET_FP_REPORT names a file for the tables.
func TestFalsePositives(t *testing.T) {
	var report strings.Builder
	report.WriteString("## Full scans\n\n")
	run(t, &report, "repos.yaml", 1, func(t *testing.T, dir string) []*finding.Finding {
		return scantest.Scan(t, scantest.Directory(t, dir))
	})
	report.WriteString("\n## Pull request scans\n\n")
	run(t, &report, "changes.yaml", 2, func(t *testing.T, dir string) []*finding.Finding {
		return scantest.ScanAgainst(t, scantest.Directory(t, dir), "HEAD^")
	})
	t.Log("\n" + report.String())
	if p := os.Getenv("VET_FP_REPORT"); p != "" {
		require.NoError(t, os.WriteFile(p, []byte(report.String()), 0o644))
	}
}

// run checks out each entry of a list with depth commits of history, scans
// it, and writes its row to the table.
func run(t *testing.T, table *strings.Builder, list string, depth int, scan func(*testing.T, string) []*finding.Finding) {
	t.Helper()
	data, err := os.ReadFile(list)
	require.NoError(t, err)
	var repos []repo
	require.NoError(t, yaml.Unmarshal(data, &repos))

	table.WriteString("| Project | Attack findings | Other findings |\n| --- | --- | --- |\n")
	for _, r := range repos {
		require.Len(t, r.Commit, 40, "%s: pin a full commit hash", r.Name)
		name := r.Name + "@" + r.Commit[:8]
		t.Run(name, func(t *testing.T) {
			var attack, other []string
			for _, f := range scan(t, checkout(t, r, depth)) {
				line := fmt.Sprintf("`%s` %s", f.ControlID, f.Path())
				switch {
				case f.Attack != nil:
					attack = append(attack, line)
					assert.Failf(t, "an attack finding on a clean project", "%s: %s", line, f.Title)
				case f.Family == finding.FamilyHiddenCode || f.Family == finding.FamilyAgentConfig:
					other = append(other, line)
				}
			}
			fmt.Fprintf(table, "| %s | %s | %s |\n", name, cell(attack), cell(other))
		})
	}
}

func cell(lines []string) string {
	if len(lines) == 0 {
		return "none"
	}
	return strings.Join(lines, "<br>")
}

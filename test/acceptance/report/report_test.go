package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acc "github.com/safedep/vet/v2/test/acceptance"
)

func TestStatusesFromJUnit(t *testing.T) {
	xmlIn := `<testsuites><testsuite>
	  <testcase name="TestAcceptance/npm/guard/malware-block"></testcase>
	  <testcase name="TestAcceptance/npm/install/clean-allow"><failure message="boom">boom</failure></testcase>
	  <testcase name="TestAcceptance/cloud/analyzer/authenticated-query-blocks-malware"><skipped message="no cloud credentials"></skipped></testcase>
	  <testcase name="TestAcceptance/npm/guard"></testcase>
	</testsuite></testsuites>`

	got, err := statusesFromJUnit([]byte(xmlIn))
	require.NoError(t, err)
	assert.Equal(t, StatusPass, got["npm/guard/malware-block"])
	assert.Equal(t, StatusFail, got["npm/install/clean-allow"])
	assert.Equal(t, StatusSkip, got["cloud/analyzer/authenticated-query-blocks-malware"])
	assert.Equal(t, StatusPass, got["npm/guard"]) // parent aggregate; ignored later (not a catalog id)
}

func TestStatusesFromJUnitIgnoresNonAcceptance(t *testing.T) {
	xmlIn := `<testsuites><testsuite>
	  <testcase name="TestCatalogIntegrity"></testcase>
	  <testcase name="TestAcceptance/setup/install/shims-created"></testcase>
	</testsuite></testsuites>`

	got, err := statusesFromJUnit([]byte(xmlIn))
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, StatusPass, got["setup/install/shims-created"])
}

func TestSummarize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  category: npm
  tier: P0
  guarantee: x
- id: pnpm/guard/malware-block
  category: pnpm
  tier: P0
  guarantee: y
`), 0o600))
	cat, err := acc.LoadCatalog(path)
	require.NoError(t, err)

	sum := summarize(cat, map[string]Status{"npm/guard/malware-block": StatusPass}, nil)
	assert.Equal(t, 1, sum.Counts[StatusPass])
	assert.Equal(t, 1, sum.Counts[StatusGap]) // pnpm has no result and no script
	assert.Len(t, sum.Rows, 2)
}

func TestSummarizeUnknownWhenScriptPresentButNoResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  category: npm
  tier: P0
  guarantee: x
- id: pnpm/guard/malware-block
  category: pnpm
  tier: P0
  guarantee: y
`), 0o600))
	cat, err := acc.LoadCatalog(path)
	require.NoError(t, err)

	// npm has a script on disk but no result; pnpm has neither.
	scripts := map[string]bool{"npm/guard/malware-block": true}
	sum := summarize(cat, map[string]Status{}, scripts)
	assert.Equal(t, 1, sum.Counts[StatusUnknown]) // scripted but unreported
	assert.Equal(t, 1, sum.Counts[StatusGap])     // no script yet
}

func TestRenderShowsFailureSnippetAndCoverage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  category: npm
  tier: P0
  guarantee: a malware verdict is never installed
- id: npm/install/clean-allow
  category: npm
  tier: P1
  guarantee: a clean package installs
`), 0o600))
	cat, err := acc.LoadCatalog(path)
	require.NoError(t, err)

	results := map[string]result{
		"npm/guard/malware-block": {status: StatusPass},
		"npm/install/clean-allow": {status: StatusFail, message: "unexpected command success"},
	}
	statuses := map[string]Status{}
	for id, r := range results {
		statuses[id] = r.status
	}

	var b strings.Builder
	require.NoError(t, render(&b, summarize(cat, statuses, nil), results))
	out := b.String()

	assert.Contains(t, out, "npm/guard/malware-block")
	assert.Contains(t, out, "unexpected command success")
	assert.Contains(t, out, "1/1") // P0 coverage: 1 pass of 1
	assert.Contains(t, out, "## npm")
}

func TestParseJUnitRejectsMalformed(t *testing.T) {
	_, err := statusesFromJUnit([]byte("<testsuites><not-closed"))
	assert.Error(t, err)
}

func TestSnippetPrefersAssertionLineOverTestLogNoise(t *testing.T) {
	body := `=== RUN   TestAcceptance/npm/guard/malware-block
=== PAUSE TestAcceptance/npm/guard/malware-block
    testscript.go:584: WORK=$WORK
        PATH=/usr/bin
        HOME=/no-home
        > ! exec vet scan
        FAIL: scripts/npm/guard/malware-block.txtar:11: unexpected command success`
	got := snippet(&xmlNode{Message: "=== RUN   TestAcceptance/npm/guard/malware-block", Body: body})
	assert.Equal(t, "FAIL: scripts/npm/guard/malware-block.txtar:11: unexpected command success", got)
}

func TestSnippetSuppressesRunHeaderOnlyBody(t *testing.T) {
	got := snippet(&xmlNode{Message: "=== RUN   TestAcceptance/cloud/analyzer/x", Body: "=== RUN   TestAcceptance/cloud/analyzer/x\n"})
	assert.Equal(t, "", got)
}

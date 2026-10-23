package prcomment

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

var agentYAML = regexp.MustCompile("(?s)<summary>For AI agents</summary>\n\n````yaml\n(.*?)\n````\n")

func upgradeInput(t *testing.T) *input {
	t.Helper()
	c := newInput(t, plugintest.UpgradeReport())
	c.artifact, c.links.RunID = "vet-report", "99"
	return c
}

func TestAgentBlock(t *testing.T) {
	s := plugintest.UpgradeReport()
	c := upgradeInput(t)
	body := c.body()
	m := agentYAML.FindStringSubmatch(body)
	require.Len(t, m, 2)
	var got agentBlock
	require.NoError(t, yaml.Unmarshal([]byte(m[1]), &got))
	assert.Equal(t, "v1", got.Version)
	assert.Equal(t, "fail", got.Gate)
	assert.Equal(t, "gh run download 99 -R acme/app -n vet-report -D vet-report", got.Report)
	require.Len(t, got.Causes, 1)
	assert.ElementsMatch(t, s.TrailerValue.Gate.FindingIDs, got.Causes[0].Findings, "the block lists each blocking finding")
	assert.Equal(t, "2026-10-23T11:16:31Z", got.Causes[0].WaitUntil)
	assert.Equal(t, "pkg:npm/pnpm@12.15.0", got.Causes[0].Subject)
	assert.Len(t, got.Other, 9)
	assert.Contains(t, body, "Report file: `gh run download 99 -R acme/app -n vet-report -D vet-report`")
}

func TestNoDownloadWithNoArtifact(t *testing.T) {
	body := newInput(t, plugintest.UpgradeReport()).body()
	assert.NotContains(t, body, "gh run download")
	m := agentYAML.FindStringSubmatch(body)
	require.Len(t, m, 2)
	assert.NotContains(t, m[1], "report:")
}

// A value that YAML quotes, with backticks and a fence, stays one value.
func TestAgentBlockKeepsTheFence(t *testing.T) {
	s := plugintest.UpgradeReport()
	for _, f := range s.FindingList {
		if f.Family == finding.FamilyCooldown {
			f.Remediation.Summary, f.Remediation.Command = "run `x`: now ```", "- `rm -rf`: ````"
		}
	}
	m := agentYAML.FindStringSubmatch(newInput(t, s).body())
	require.Len(t, m, 2)
	var got agentBlock
	require.NoError(t, yaml.Unmarshal([]byte(m[1]), &got))
	require.Len(t, got.Causes, 1)
	assert.Equal(t, "run `x`: now ```", got.Causes[0].Fix)
	assert.Equal(t, "- `rm -rf`: ````", got.Causes[0].Command)
}

func TestAnnotations(t *testing.T) {
	c := upgradeInput(t)
	c.links.Prefix = "web/"
	assert.Equal(t, []ci.Annotation{{
		Level: ci.AnnotationError, Path: "web/package.json", Line: 119, Title: "vet: Published 1 day ago",
		Text: `npm/pnpm@12.15.0 and 14 more: Keep "packageManager" at pnpm@12.8.2 in package.json, or wait until 2026-10-23. The wait ends at 2026-10-23 11:17 UTC.`,
	}}, c.annotations())

	c.links.NoFiles = true
	assert.Empty(t, c.annotations(), "no annotation for a target outside the checkout")
}

// An attack that a gate of policy rules does not fail gets a warning in
// the diff, not an error.
func TestAnnotationOfAnAttackOutsideTheGate(t *testing.T) {
	s := pkgReport("left-pad-two")
	s.FindingList = append(s.FindingList, pullRequest(report.GateFail).FindingList[0])
	c := newInput(t, s)
	got := c.annotations()
	require.Len(t, got, 2)
	assert.Equal(t, ci.AnnotationError, got[0].Level)
	assert.Equal(t, ci.AnnotationWarning, got[1].Level)
	assert.Equal(t, "vet: Malicious package", got[1].Title)
}

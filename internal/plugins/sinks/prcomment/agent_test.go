package prcomment

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

var agentYAML = regexp.MustCompile("(?s)<summary>For AI agents</summary>\n\n```yaml\n(.*?)```")

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

func TestAgentBlockKeepsTheFence(t *testing.T) {
	s := plugintest.UpgradeReport()
	s.FindingList[0].Remediation.Summary = "Run ```\n</details> now"
	body := newInput(t, s).body()
	m := agentYAML.FindStringSubmatch(body)
	require.Len(t, m, 2)
	assert.NotContains(t, m[1], "`")
}

func TestAnnotations(t *testing.T) {
	c := upgradeInput(t)
	c.links.Prefix = "web/"
	assert.Equal(t, []ci.Annotation{{
		Path: "web/pnpm-lock.yaml", Line: 92, Title: "vet: Published 1 day ago",
		Text: "npm/pnpm@12.15.0 and 14 more: Keep version 12.8.2, or wait until 2026-10-23. The wait ends at 2026-10-23 11:17 UTC.",
	}}, c.annotations())

	c.links.NoFiles = true
	assert.Empty(t, c.annotations(), "no annotation for a target outside the checkout")
}

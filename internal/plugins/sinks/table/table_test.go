package table

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/theme"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

// withWidth renders in rich mode at a width of n cells.
func withWidth(t *testing.T, n int) {
	t.Helper()
	prev := output.CurrentMode()
	output.SetMode(output.Rich)
	output.SetWidthOverride(n)
	t.Cleanup(func() {
		output.SetWidthOverride(0)
		output.SetMode(prev)
	})
}

func write(t *testing.T, options plugin.MapConfig, r *plugintest.MemState) string {
	t.Helper()
	s, err := New(options)
	require.NoError(t, err)
	return string(plugintest.TestSink(t, s, r))
}

// vulnReport has 3 vulnerabilities of django, 2 of requests, and one
// finding of another control on django. fixed sets the fixed version of the
// first findings.
func vulnReport(fixed ...string) *plugintest.MemState {
	django := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "django", "2.2.0"), Line: 2}
	requests := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "requests", "2.19.0"), Line: 1}
	vuln := func(p *model.Package, id string, sev finding.Severity) *finding.Finding {
		f := finding.ForPackage(finding.Meta{
			ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev,
			Title: id + " in " + p.ID.String() + ": summary of " + id,
		}, "requirements.txt", p, finding.Key{Discriminator: id})
		return &f
	}
	fs := []*finding.Finding{
		vuln(django, "GHSA-d1", finding.SeverityHigh),
		vuln(django, "GHSA-d2", finding.SeverityCritical),
		vuln(django, "GHSA-d3", finding.SeverityHigh),
		vuln(requests, "GHSA-r1", finding.SeverityMedium),
		vuln(requests, "GHSA-r2", finding.SeverityLow),
	}
	for i, v := range fixed {
		fs[i].Remediation = &finding.Remediation{FixedVersion: v}
	}
	score := finding.ForPackage(finding.Meta{
		ControlID: "scorecard-low", Family: finding.FamilyReputation, Severity: finding.SeverityInfo, Title: "Low OpenSSF Scorecard",
	}, "requirements.txt", django, finding.Key{})
	s := plugintest.SampleReport()
	s.FindingList = append(fs, &score)
	s.CapabilityList = nil
	return s
}

// rowsOf returns the rows of the findings table, with single spaces.
func rowsOf(out string) []string {
	var rows []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "│ [") {
			rows = append(rows, strings.Join(strings.Fields(strings.ReplaceAll(l, "│", " ")), " "))
		}
	}
	return rows
}

func short(f *finding.Finding) string { return report.ShortID(f.ID, 10) }

func TestGroupsTheVulnerabilitiesOfAPackage(t *testing.T) {
	withWidth(t, 160)
	r := vulnReport()
	got := write(t, nil, r)
	assert.Equal(t, []string{
		"[CRITICAL] " + short(r.FindingList[1]) + " vulnerability pypi/django@2.2.0 3 vulnerabilities: 1 critical, 2 high requirements.txt:2",
		"[MEDIUM] " + short(r.FindingList[3]) + " vulnerability pypi/requests@2.19.0 2 vulnerabilities: 1 medium, 1 low requirements.txt:1",
		"[INFO] " + short(r.FindingList[5]) + " scorecard-low pypi/django@2.2.0 Low OpenSSF Scorecard requirements.txt:2",
	}, rowsOf(got))
	assert.Contains(t, got, "› 5 vulnerabilities in 2 packages. vet report show --all lists each finding.")
	assert.NotContains(t, got, "Details:", "the scan view names the finding show command")
}

func TestAllListsEachFinding(t *testing.T) {
	withWidth(t, 160)
	r := vulnReport()
	got := write(t, plugin.MapConfig{"all": true}, r)
	rows := rowsOf(got)
	require.Len(t, rows, 6)
	assert.Equal(t, "[CRITICAL] "+short(r.FindingList[1])+" vulnerability pypi/django@2.2.0 GHSA-d2: summary of GHSA-d2 requirements.txt:2", rows[0])
	assert.NotContains(t, got, "vulnerabilities in")
	assert.NotContains(t, got, "--all")
}

func TestLimitCountsRows(t *testing.T) {
	withWidth(t, 160)
	cases := []struct {
		name    string
		options plugin.MapConfig
		rows    int
		hint    string
	}{
		{
			name: "grouped", options: plugin.MapConfig{"limit": 2}, rows: 2,
			hint: "› 5 vulnerabilities in 2 packages. The table shows 2 of 3 rows.\n› vet report show --all lists each finding.",
		},
		{name: "flat", options: plugin.MapConfig{"all": true, "limit": 2}, rows: 6},
		{name: "default", rows: 3, hint: "› 5 vulnerabilities in 2 packages. vet report show --all lists each finding."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := write(t, tc.options, vulnReport())
			assert.Len(t, rowsOf(got), tc.rows)
			if tc.hint != "" {
				assert.Contains(t, got, tc.hint)
			}
		})
	}
}

func TestLimitOfSingleRows(t *testing.T) {
	withWidth(t, 120)
	got := write(t, plugin.MapConfig{"limit": 1}, plugintest.SampleReport())
	assert.Contains(t, got, "› 1 more finding. vet report show --all lists each finding.")
	assert.Contains(t, got, "› 1 suppressed finding. vet report show -o json lists it.")
	assert.NotContains(t, got, "tj-actions/changed-files@v44")

	got = write(t, nil, plugintest.SampleReport())
	assert.NotContains(t, got, "more finding")
	assert.Contains(t, got, "tj-actions/changed-files@v44")

	_, err := New(plugin.MapConfig{"limit": -1})
	assert.Error(t, err)
}

func TestFixVersion(t *testing.T) {
	withWidth(t, 160)
	cases := []struct {
		name  string
		fixed []string
		want  string
	}{
		{name: "each finding has a fix", fixed: []string{"2.2.10", "3.0.1", "2.2.24"}, want: "3 vulnerabilities: 1 critical, 2 high (fix 3.0.1) requirements.txt:2"},
		{name: "one finding has no fix", fixed: []string{"2.2.10", "3.0.1"}, want: "3 vulnerabilities: 1 critical, 2 high requirements.txt:2"},
		{name: "the PyPI order", fixed: []string{"2.2.28", "3.0rc1", "2.2.24"}, want: "(fix 3.0rc1)"},
		{name: "two spellings of one version", fixed: []string{"3.0", "3.0.0", "2.2.24"}, want: "(fix 3.0.0)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Contains(t, rowsOf(write(t, nil, vulnReport(tc.fixed...)))[0], tc.want)
		})
	}
}

func TestCountTextFitsTheRoom(t *testing.T) {
	r := vulnReport()
	django := row(r.FindingList[:3])
	cases := []struct {
		name string
		room int
		want string
	}{
		{name: "room for the total", room: 40, want: "3 vulnerabilities: 1 critical, 2 high"},
		{name: "no room for the total", room: 30, want: "1 critical, 2 high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, django.text(tc.room))
		})
	}
}

func TestColumnsFollowTheWidth(t *testing.T) {
	cases := []struct {
		name    string
		width   int
		delta   bool
		headers []string
	}{
		{name: "narrow", width: 80, headers: []string{"SEVERITY", "ID", "SUBJECT", "FINDING"}},
		{name: "wide", width: 120, headers: []string{"SEVERITY", "ID", "CONTROL", "SUBJECT", "FINDING", "WHERE"}},
		{name: "narrow pull request", width: 80, delta: true, headers: []string{"SEVERITY", "ID", "CHANGE", "SUBJECT", "FINDING"}},
		{name: "wide pull request", width: 130, delta: true, headers: []string{"SEVERITY", "ID", "CONTROL", "CHANGE", "SUBJECT", "FINDING", "WHERE"}},
		{name: "no room for the control", width: 120, delta: true, headers: []string{"SEVERITY", "ID", "CHANGE", "SUBJECT", "FINDING", "WHERE"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withWidth(t, tc.width)
			r := vulnReport()
			if tc.delta {
				h := *r.Header()
				h.Scan.Mode = report.ScanModeDelta
				r.HeaderValue = &h
				for i, f := range r.FindingList {
					f.Change = model.ChangeUpgraded
					if i == len(r.FindingList)-1 {
						f.Change = model.ChangeAdded
					}
				}
			}
			got := write(t, nil, r)
			var header string
			for _, l := range strings.Split(got, "\n") {
				if strings.Contains(l, "SEVERITY") {
					header = l
				}
				assert.LessOrEqual(t, ansi.StringWidth(l), tc.width)
			}
			assert.Equal(t, tc.headers, strings.Fields(strings.ReplaceAll(header, "│", " ")))
		})
	}
}

func TestPullRequestTable(t *testing.T) {
	withWidth(t, 120)
	output.SetMode(output.Plain)
	r := plugintest.SampleReport()
	h := *r.Header()
	h.Scan.Mode = report.ScanModeDelta
	r.HeaderValue = &h
	r.CapabilityList, r.InventoryList = nil, nil
	r.ManifestList[0].Packages[0].Change = model.ChangeAdded
	for _, f := range r.FindingList {
		f.Change = model.ChangeAdded
	}

	got := write(t, nil, r)
	assert.Contains(t, got, "Changed: 1", "the card counts the changed packages, not every package")
	assert.NotContains(t, got, "CHANGE", "each row has the same change")
	assert.Contains(t, got, "Each finding is on a package or a file that the change adds.")

	r.FindingList[1].Change = model.ChangeModified
	got = write(t, nil, r)
	assert.Contains(t, got, "CHANGE")
	assert.NotContains(t, got, "Each finding is on")
}

func TestBadgeRoles(t *testing.T) {
	assert.Equal(t, map[finding.Severity]theme.Role{
		finding.SeverityCritical: theme.RoleCritical,
		finding.SeverityHigh:     theme.RoleHigh,
		finding.SeverityMedium:   theme.RoleMedium,
		finding.SeverityLow:      theme.RoleLow,
		finding.SeverityInfo:     theme.RoleInfo,
	}, severityRoles)
}

func TestCapabilities(t *testing.T) {
	cases := []struct {
		name    string
		width   int
		options plugin.MapConfig
		noCaps  bool
		want    []string
		notWant []string
	}{
		{
			name: "wide", width: 120,
			want: []string{"AI and crypto: 1 AI, 1 crypto", "OpenAI SDK Chat Completions", "src/chat.py:12", "MD5", "hash, [WEAK]", "CALL", "openai//OpenAI"},
		},
		{
			name: "narrow", width: 80,
			want:    []string{"MD5", "src/cache.py:3"},
			notWant: []string{"CALL", "hashlib//md5"},
		},
		{
			name: "limit 1 keeps AI first", width: 120, options: plugin.MapConfig{"limit": 1},
			want:    []string{"OpenAI SDK", "› 1 more capability. vet report capability list lists each one."},
			notWant: []string{"src/cache.py"},
		},
		{
			name: "no capabilities", width: 120, noCaps: true,
			notWant: []string{"AI and crypto"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withWidth(t, tc.width)
			r := plugintest.SampleReport()
			if tc.noCaps {
				r.CapabilityList = nil
			}
			got := write(t, tc.options, r)
			for _, w := range tc.want {
				assert.Contains(t, got, w)
			}
			for _, w := range tc.notWant {
				assert.NotContains(t, got, w)
			}
		})
	}
}

func TestTagsPutTheWeakBadgeLast(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want string
	}{
		{name: "weak and others", tags: []string{"cryptography", "weak", "hash"}, want: "hash, [WEAK]"},
		{name: "weak alone", tags: []string{"cryptography", "weak"}, want: "[WEAK]"},
		{name: "no weak", tags: []string{"ai", "llm", "agent"}, want: "llm, agent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tags(&report.Capability{Tags: tc.tags}))
		})
	}
}

func TestCapabilityWhereCountsTheOtherCalls(t *testing.T) {
	c := &report.Capability{Occurrences: []report.Occurrence{{File: "a.py", Line: 3}, {File: "b.py", Line: 9}, {File: "c.py"}}}
	assert.Equal(t, "a.py:3 (+2)", CapabilityWhere(c))
	assert.Empty(t, CapabilityWhere(&report.Capability{}))
}

func TestEmptyScanWritesNothing(t *testing.T) {
	s, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	r := plugintest.SampleReport()
	r.ManifestList, r.FindingList, r.CapabilityList, r.InventoryList = nil, nil, nil, nil
	assert.Empty(t, string(plugintest.TestSink(t, s, r)))
}

func TestWrap(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		width int
		want  string
	}{
		{name: "fits", text: "Malicious package", width: 20, want: "Malicious package"},
		{name: "two lines", text: "Malicious package", width: 10, want: "Malicious\npackage"},
		{name: "cut at a word", text: "Third-party action is not pinned to a commit", width: 12, want: "Third-party\naction is…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wrap(tc.text, tc.width, textLines))
		})
	}
}

func TestToolTable(t *testing.T) {
	withWidth(t, 120)
	r := plugintest.SampleReport()
	r.InventoryList = []*report.InventoryItem{
		{Kind: report.InventorySkill, Name: "review"},
		{Kind: report.InventoryMCPServer, Name: "db", Client: "cursor"},
		{Kind: report.InventoryAITool, Name: "Claude Code"},
		{Kind: report.InventoryMCPServer, Name: "aws"},
		{Kind: "browser-extension", Name: "x"},
	}
	r.CapabilityList = nil
	got := write(t, nil, r)
	assert.Contains(t, got, "Tools: 1 AI tool, 2 MCP servers, 1 agent skill, 1 other tool")
	var names []string
	for _, l := range strings.Split(got, "\n") {
		if f := strings.Fields(strings.ReplaceAll(l, "│", " ")); strings.HasPrefix(l, "│") && len(f) > 1 && slices.Contains([]string{"AI", "MCP", "agent", "browser-extension"}, f[0]) {
			names = append(names, l)
		}
	}
	require.Len(t, names, 5)
	for i, want := range []string{"Claude Code", "aws", "db", "review", "x"} {
		assert.Contains(t, names[i], want, "the tools sort by kind, then by name")
	}

	got = write(t, plugin.MapConfig{"limit": 2}, r)
	assert.Contains(t, got, "› 3 more tools. vet report show --all lists each one.")
}

func TestFixVersionWithNoOrder(t *testing.T) {
	action := &model.Package{ID: model.MustPackageVersion(model.EcosystemGitHubActions, "actions/checkout", "v3")}
	var r row
	for i, v := range []string{"v4", "v5", "v4"} {
		f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "t"},
			".github/workflows/ci.yml", action, finding.Key{Discriminator: strconv.Itoa(i)})
		f.Remediation = &finding.Remediation{FixedVersion: v}
		r = append(r, &f)
	}
	assert.Equal(t, "v4, v5", r.fix(), "vet does not pick a version that it cannot order")
}

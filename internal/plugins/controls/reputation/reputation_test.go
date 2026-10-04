package reputation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

var now = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func ago(days int) *time.Time {
	t := now.Add(-time.Duration(days) * 24 * time.Hour)
	return &t
}

func run(t *testing.T, opts map[string]any, p *model.Package) []string {
	t.Helper()
	c, err := New(plugin.MapConfig(opts))
	require.NoError(t, err)
	c.(*Control).now = func() time.Time { return now }
	m := &model.Manifest{ID: "m", Path: "package-lock.json", Kind: model.ManifestKindLockfile, Packages: []*model.Package{p}}
	var out []string
	for _, f := range plugintest.TestControl(t, c, m, nil) {
		out = append(out, f.ControlID)
	}
	return out
}

func pkg(eco model.Ecosystem, name, version string, in *model.Insight) *model.Package {
	return &model.Package{ID: model.MustPackageVersion(eco, name, version), Insight: in}
}

func TestReputation(t *testing.T) {
	few := &model.Insight{Downloads: 12}
	cases := []struct {
		name string
		opts map[string]any
		pkg  *model.Package
		want []string
	}{
		{"typo of a popular npm name", nil, pkg(model.EcosystemNpm, "expresss", "1.0.0", few), []string{IDTyposquat}},
		{"swapped letters", nil, pkg(model.EcosystemNpm, "lodahs", "1.0.0", few), []string{IDTyposquat}},
		{"homoglyph", nil, pkg(model.EcosystemPyPI, "reqvests", "1.0.0", &model.Insight{}), []string{IDTyposquat}},
		{"separator", nil, pkg(model.EcosystemPyPI, "pythondateutil", "1.0.0", few), []string{IDTyposquat}},
		{"another word with one more letter at the start", nil, pkg(model.EcosystemNpm, "args", "5.0.3", few), nil},
		{"one more letter at the end", nil, pkg(model.EcosystemNpm, "lodashh", "1.0.0", few), []string{IDTyposquat}},
		{"the popular package", nil, pkg(model.EcosystemNpm, "express", "4.19.2", few), nil},
		{"a popular near name", nil, pkg(model.EcosystemNpm, "preact", "10.0.0", &model.Insight{Downloads: 5_000_000}), nil},
		{"no data fails open", nil, pkg(model.EcosystemNpm, "expresss", "1.0.0", nil), nil},
		{"pypi case and separators are one name", nil, pkg(model.EcosystemPyPI, "Python_Dateutil", "2.9.0", few), nil},
		{"new and unpopular", nil, pkg(model.EcosystemNpm, "brand-new-thing", "0.0.1", &model.Insight{FirstPublishedAt: ago(3), Downloads: 5}), []string{IDNewPackage}},
		{"new and popular", nil, pkg(model.EcosystemNpm, "brand-new-thing", "0.0.1", &model.Insight{FirstPublishedAt: ago(3), Downloads: 50000}), nil},
		{"old and unpopular", nil, pkg(model.EcosystemNpm, "brand-new-thing", "0.0.1", &model.Insight{FirstPublishedAt: ago(400), Downloads: 5}), nil},
		{"new with a shorter window", map[string]any{"new_package_days": 2}, pkg(model.EcosystemNpm, "brand-new-thing", "0.0.1", &model.Insight{FirstPublishedAt: ago(3), Downloads: 5}), nil},
		{"starjacking", nil, pkg(model.EcosystemNpm, "some-fork", "1.0.0", &model.Insight{Stars: 90000, Downloads: 3, SourceRepo: "https://github.com/facebook/react"}), []string{IDStarjacking}},
		{"no download count is not starjacking", nil, pkg(model.EcosystemCargo, "regex-syntax", "0.8.11", &model.Insight{Stars: 4039, SourceRepo: "https://github.com/rust-lang/regex"}), nil},
		{"a new package in the scope of its repository owner", nil, &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "@pnpm/exe.linux-x64", "12.0.0"), Insight: &model.Insight{FirstPublishedAt: ago(3), Stars: 36000, SourceRepo: "https://github.com/pnpm/pnpm"}}, nil},
		{"a new package in a scope that copies the owner", nil, &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "@pnpmm/exe.linux-x64", "12.0.0"), Insight: &model.Insight{FirstPublishedAt: ago(3), Stars: 36000, SourceRepo: "https://github.com/pnpm/pnpm"}}, []string{IDNewPackage}},
		{"new with no download count", nil, pkg(model.EcosystemNpm, "brand-new-thing", "0.0.1", &model.Insight{FirstPublishedAt: ago(3)}), []string{IDNewPackage}},
		{"a near name with its own popular repository", nil, pkg(model.EcosystemNpm, "enquirer", "2.4.1", &model.Insight{Stars: 7700, SourceRepo: "https://github.com/enquirer/enquirer"}), nil},
		{"a squat that claims the repository it copies", nil, pkg(model.EcosystemNpm, "expresss", "1.0.0", &model.Insight{Stars: 65000, SourceRepo: "https://github.com/expressjs/express.git"}), []string{IDTyposquat}},
		{
			"internal name from the public registry",
			map[string]any{"internal_names": []any{"@acme/*"}},
			&model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "@acme/auth", "9.9.9"), Resolved: "https://registry.npmjs.org/@acme/auth/-/auth-9.9.9.tgz"},
			[]string{IDConfusion},
		},
		{
			"a PyPI internal name in another spelling",
			map[string]any{"internal_names": []any{"acme-*"}},
			&model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "Acme.Utils", "1.0.0"), Resolved: "https://files.pythonhosted.org/packages/acme_utils-1.0.0.tar.gz"},
			[]string{IDConfusion},
		},
		{
			"internal name from the internal registry",
			map[string]any{"internal_names": []any{"@acme/*"}},
			&model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "@acme/auth", "1.0.0"), Resolved: "https://npm.acme.example/@acme/auth/-/auth-1.0.0.tgz"}, nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, run(t, tc.opts, tc.pkg))
		})
	}
}

func TestChangeChecks(t *testing.T) {
	jump := pkg(model.EcosystemNpm, "left-pad", "4.0.0", nil)
	jump.Change, jump.PreviousVersion = model.ChangeUpgraded, "1.3.0"
	assert.Equal(t, []string{IDVersionAnomaly}, run(t, nil, jump))

	older := pkg(model.EcosystemNpm, "left-pad", "1.4.0", &model.Insight{PublishedAt: ago(30)})
	older.Change, older.PreviousVersion, older.PreviousInsight = model.ChangeUpgraded, "1.3.0", &model.Insight{PublishedAt: ago(10)}
	assert.Equal(t, []string{IDVersionAnomaly}, run(t, nil, older))

	normal := pkg(model.EcosystemNpm, "left-pad", "2.0.0", nil)
	normal.Change, normal.PreviousVersion = model.ChangeUpgraded, "1.3.0"
	assert.Empty(t, run(t, nil, normal))

	ai := pkg(model.EcosystemPyPI, "anthropic", "0.40.0", nil)
	ai.Change = model.ChangeAdded
	assert.Equal(t, []string{IDAIBOM}, run(t, nil, ai))
	ai.Change = model.ChangeNone
	assert.Empty(t, run(t, nil, ai), "a full scan has no new capability")
}

func TestDistance(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		d    int
	}{{"react", "react", 0}, {"react", "raect", 1}, {"react", "reactt", 1}, {"react", "rect", 1}, {"lodash", "loadsh", 1}, {"abc", "xyz", 3}} {
		assert.Equal(t, tc.d, distance(tc.a, tc.b), tc.a+" "+tc.b)
	}
}

func TestOptions(t *testing.T) {
	_, err := New(plugin.MapConfig(map[string]any{"internal_names": []any{"["}}))
	assert.Error(t, err)
}

func TestAICapabilityDelta(t *testing.T) {
	c := &Control{}
	occ := []report.Occurrence{{File: "agent.py", Line: 7, Language: "python"}}
	s := plugintest.NewMemState()
	s.CapabilityList = []*report.Capability{
		{ID: "openai.client", Product: "OpenAI SDK", Service: "Chat", Tags: []string{"ai", "llm"}, Change: model.ChangeAdded, Occurrences: occ},
		{ID: "anthropic.client", Tags: []string{"ai"}, Change: model.ChangeUnchanged, Occurrences: occ},
		{ID: "crypto.md5", Tags: []string{"cryptography"}, Change: model.ChangeAdded, Occurrences: occ},
		{ID: "cohere.client", Tags: []string{"ai"}, Occurrences: occ},
	}
	fs, err := c.EvaluateApplication(context.Background(), s)
	require.NoError(t, err)
	require.Len(t, fs, 1, "only an added AI capability")
	f := fs[0]
	require.NoError(t, f.Validate())
	assert.Equal(t, IDAIBOM, f.ControlID)
	assert.Equal(t, finding.SubjectApplication, f.Subject.Kind)
	assert.Equal(t, "openai.client", f.Subject.Application.SignatureID)
	assert.Equal(t, model.ChangeAdded, f.Change)
	assert.Equal(t, "The change adds a call to OpenAI SDK Chat", f.Title)
	assert.Equal(t, &finding.Locus{Path: "agent.py", StartLine: 7, EndLine: 7}, f.Locus)
	assert.Equal(t, finding.ForApplication(finding.Meta{ControlID: IDAIBOM}, ".", "openai.client").ID, f.ID, "the id holds the control, the root and the signature")
}

package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

var meta = Meta{
	ControlID: "malware",
	Family:    FamilyMalware,
	Severity:  SeverityCritical,
	Title:     "Malicious package",
}

func pkg(version string, line int) *model.Package {
	return &model.Package{
		ID:   model.MustPackageVersion(model.EcosystemNpm, "evil", version),
		Line: line,
	}
}

func TestConstructorsKeepOneSubject(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		kind SubjectKind
	}{
		{"package", ForPackage(meta, "package-lock.json", pkg("1.0.0", 10), Key{}), SubjectPackage},
		{"file", ForFile(meta, Locus{Path: ".github/workflows/ci.yml", StartLine: 3}, Key{}), SubjectFile},
		{"manifest", ForManifest(meta, "package-lock.json", model.EcosystemNpm, Key{}), SubjectManifest},
		{"application", ForApplication(meta, "apps/agent", "sig-1"), SubjectApplication},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.f.Validate())
			assert.Equal(t, tc.kind, tc.f.Subject.Kind)
			assert.Regexp(t, `^f-[0-9a-f]{16}$`, tc.f.ID)
			assert.Equal(t, ConfidenceHigh, tc.f.Confidence)
		})
	}
}

func TestForPackageFields(t *testing.T) {
	p := pkg("1.0.0", 10)
	p.Direct = true
	p.Change = model.ChangeAdded
	f := ForPackage(meta, "package-lock.json", p, Key{})
	assert.Equal(t, "pkg:npm/evil@1.0.0", f.Subject.Package.PURL)
	assert.True(t, f.Subject.Package.Direct)
	assert.Equal(t, model.ChangeAdded, f.Change)
	require.NotNil(t, f.Locus)
	assert.Equal(t, 10, f.Locus.StartLine)
}

func TestValidate(t *testing.T) {
	ok := ForManifest(Meta{ControlID: "c", Family: FamilyLockfile, Severity: SeverityHigh, Title: "t"}, "a.lock", model.EcosystemNpm, Key{})
	require.NoError(t, ok.Validate())

	cases := []struct {
		name   string
		mutate func(f *Finding)
	}{
		{"no id", func(f *Finding) { f.ID = "" }},
		{"no control", func(f *Finding) { f.ControlID = "" }},
		{"bad severity", func(f *Finding) { f.Severity = "urgent" }},
		{"bad family", func(f *Finding) { f.Family = "x" }},
		{"bad confidence", func(f *Finding) { f.Confidence = "sure" }},
		{"bad change", func(f *Finding) { f.Change = "MOVED" }},
		{"two subjects", func(f *Finding) { f.Subject.File = &FileSubject{Path: "x"} }},
		{"no subject", func(f *Finding) { f.Subject.Manifest = nil }},
		{"kind mismatch", func(f *Finding) { f.Subject.Kind = SubjectFile }},
		{"no title", func(f *Finding) { f.Title = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ok
			m := *ok.Subject.Manifest
			f.Subject.Manifest = &m
			tc.mutate(&f)
			assert.Error(t, f.Validate())
		})
	}
}

func TestSeverity(t *testing.T) {
	s, err := ParseSeverity(" HIGH ")
	require.NoError(t, err)
	assert.Equal(t, SeverityHigh, s)
	assert.True(t, SeverityCritical.AtLeast(SeverityHigh))
	assert.False(t, SeverityLow.AtLeast(SeverityHigh))
	assert.Equal(t, []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}, Severities())
	_, err = ParseSeverity("urgent")
	assert.Error(t, err)
}

func TestFamilies(t *testing.T) {
	for _, f := range Families() {
		assert.True(t, f.Valid(), f)
	}
	assert.False(t, Family("other").Valid())
}

func TestForPackageID(t *testing.T) {
	base := ForPackage(meta, "package-lock.json", pkg("1.0.0", 10), Key{})

	cases := []struct {
		name string
		f    Finding
		same bool
	}{
		{"line moves", ForPackage(meta, "package-lock.json", pkg("1.0.0", 99), Key{}), true},
		{"severity and text change", ForPackage(Meta{ControlID: "malware", Family: FamilyMalware, Severity: SeverityLow, Title: "x"}, "package-lock.json", pkg("1.0.0", 10), Key{}), true},
		{"new version", ForPackage(meta, "package-lock.json", pkg("1.0.1", 10), Key{}), false},
		{"other manifest", ForPackage(meta, "web/package-lock.json", pkg("1.0.0", 10), Key{}), false},
		{"other advisory", ForPackage(meta, "package-lock.json", pkg("1.0.0", 10), Key{Discriminator: "GHSA-1"}), false},
		{"other control", ForPackage(Meta{ControlID: "vulnerability", Family: FamilyVulnerability, Severity: SeverityCritical, Title: "x"}, "package-lock.json", pkg("1.0.0", 10), Key{}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.same {
				assert.Equal(t, base.ID, tc.f.ID)
			} else {
				assert.NotEqual(t, base.ID, tc.f.ID)
			}
		})
	}
}

func TestForFileID(t *testing.T) {
	m := Meta{ControlID: "unpinned-action", Family: FamilyWorkflow, Severity: SeverityMedium, Title: "Unpinned action"}
	l := Locus{Path: ".github/workflows/ci.yml", StartLine: 8, Snippet: "uses:   actions/checkout@v4"}
	base := ForFile(m, l, Key{Discriminator: "actions/checkout"})

	moved := l
	moved.StartLine = 20
	moved.Snippet = " uses: actions/checkout@v4 "

	cases := []struct {
		name string
		f    Finding
		same bool
	}{
		{"line moves and whitespace changes", ForFile(m, moved, Key{Discriminator: "actions/checkout"}), true},
		{"second identical line", ForFile(m, l, Key{Discriminator: "actions/checkout", Occurrence: 1}), false},
		{"other action", ForFile(m, l, Key{Discriminator: "actions/setup-go"}), false},
		{"other file", ForFile(m, Locus{Path: ".github/workflows/release.yml", Snippet: l.Snippet}, Key{Discriminator: "actions/checkout"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.same {
				assert.Equal(t, base.ID, tc.f.ID)
			} else {
				assert.NotEqual(t, base.ID, tc.f.ID)
			}
		})
	}
}

func TestNormalizeSnippet(t *testing.T) {
	assert.Equal(t, "a b c", NormalizeSnippet("  a\tb\n  c "))
}

func TestGateRecordCause(t *testing.T) {
	cases := []struct {
		name string
		g    GateRecord
		want string
	}{
		{"one rule", GateRecord{Action: GateActionWarn, Rules: []string{"a"}}, "policy rule a"},
		{"two rules and --fail-on", GateRecord{Action: GateActionFail, Rules: []string{"a", "b"}, FailOn: "high"}, "policy rules a, b and --fail-on high"},
		{"broken rule", GateRecord{Action: GateActionFail, Broken: []string{"c"}}, "policy rule c, which did not evaluate"},
		{"--fail-on only", GateRecord{Action: GateActionFail, FailOn: "attacks"}, "--fail-on attacks"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.g.Cause())
		})
	}
}

func TestGateAction(t *testing.T) {
	cases := []struct {
		action GateAction
		valid  bool
		label  string
	}{
		{GateActionFail, true, "Blocked by"},
		{GateActionWarn, true, "Warned by"},
		{GateAction("block"), false, "Warned by"},
	}
	for _, tc := range cases {
		t.Run(string(tc.action), func(t *testing.T) {
			assert.Equal(t, tc.valid, tc.action.Valid())
			assert.Equal(t, tc.label, (&GateRecord{Action: tc.action}).Label())
		})
	}
}

func TestGateRecordShortAndEqual(t *testing.T) {
	g := &GateRecord{Action: GateActionFail, Rules: []string{"a"}, Broken: []string{"b"}, FailOn: "high"}
	assert.Equal(t, "a, b (broken), --fail-on high", g.Short())
	assert.True(t, g.Equal(&GateRecord{Action: GateActionFail, Rules: []string{"a"}, Broken: []string{"b"}, FailOn: "high"}))
	assert.False(t, g.Equal(&GateRecord{Action: GateActionFail, Rules: []string{"a"}}))
	assert.False(t, g.Equal(nil))
	assert.True(t, (*GateRecord)(nil).Equal(nil))
}

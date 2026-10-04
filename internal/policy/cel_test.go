package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

var now = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func sampleInput(published *time.Time) Input {
	p := &model.Package{
		ID:     model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0"),
		Direct: true, Change: model.ChangeAdded,
		Insight: &model.Insight{
			Licenses: []string{"MIT"}, PublishedAt: published,
			Vulnerabilities: []model.Vulnerability{{ID: "GHSA-1", Severity: "high", CVSS: 7.5}},
		},
		Malware: &model.MalwareAnalysis{Malicious: true, Confidence: "high"},
	}
	m := &model.Manifest{Path: "package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile}
	f := finding.ForPackage(finding.Meta{ControlID: "dependency-cooldown", Family: finding.FamilyCooldown, Severity: finding.SeverityHigh, Title: "t"}, m.Path, p, finding.Key{})
	return NewInput(&f, p, m, now)
}

func TestMatch(t *testing.T) {
	recent := now.Add(-50 * time.Hour)
	cases := []struct {
		name string
		expr string
		in   Input
		want bool
	}{
		{name: "days since publish", expr: "package.days_since_publish < 5", in: sampleInput(&recent), want: true},
		{name: "no publish date", expr: "package.days_since_publish < 5", in: sampleInput(nil)},
		{name: "has", expr: "has(package.days_since_publish)", in: sampleInput(nil)},
		{name: "control id", expr: `finding.control_id in ["dangerous-trigger", "dependency-cooldown"]`, in: sampleInput(nil), want: true},
		{name: "severity", expr: `finding.severity == "high" && package.direct`, in: sampleInput(nil), want: true},
		{name: "licenses", expr: `package.licenses.exists(l, l == "MIT")`, in: sampleInput(nil), want: true},
		{name: "vulnerabilities", expr: `package.vulnerabilities.exists(v, v.cvss >= 7.0)`, in: sampleInput(nil), want: true},
		{name: "malware", expr: `package.malware.malicious && !package.malware.verified`, in: sampleInput(nil), want: true},
		{name: "manifest", expr: `manifest.kind == "lockfile" && package.change == "ADDED"`, in: sampleInput(nil), want: true},
		{name: "a string that holds package", expr: `finding.title != "package.x"`, in: sampleInput(nil), want: true},
		{name: "no package", expr: `package.direct`, in: Input{Finding: FindingInput{ControlID: "unpinned-action"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Compile(tc.expr)
			require.NoError(t, err)
			got, err := e.Match(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{expr: "package.days_since_publish <", want: "Syntax error"},
		{expr: `1 + 2`, want: "not bool"},
		{expr: `"a" + 1`, want: "no matching overload"},
		{expr: "unknown.x", want: "undeclared reference to 'unknown'"},
		{expr: "package.", want: "package"},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			_, err := Compile(tc.expr)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), packageIdent, "the error names package, as the user wrote it")
		})
	}
}

func TestMatchRuntimeError(t *testing.T) {
	for _, expr := range []string{`int(finding.title) > 1`, `finding.severity`} {
		e, err := Compile(expr)
		require.NoError(t, err)
		_, err = e.Match(sampleInput(nil))
		assert.Error(t, err, expr)
	}
}

func TestRewritePackage(t *testing.T) {
	cases := []struct{ in, want string }{
		{"package.x", "vet_pkg.x"},
		{"has(package.x) && package.y", "has(vet_pkg.x) && vet_pkg.y"},
		{`"package" == package.name`, `"package" == vet_pkg.name`},
		{`'it\'s package' == package.name`, `'it\'s package' == vet_pkg.name`},
		{`r'package\' == package.name`, `r'package\' == vet_pkg.name`},
		{`"""package""" == package.name`, `"""package""" == vet_pkg.name`},
		{"x.package == mypackage || packages", "x.package == mypackage || packages"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, rewritePackage(tc.in))
		})
	}
}

func TestInputSchema(t *testing.T) {
	b, err := InputSchema()
	require.NoError(t, err)
	for _, field := range []string{"days_since_publish", "control_id", "vulnerabilities", "manifest"} {
		assert.Contains(t, string(b), `"`+field+`"`)
	}
}

func inputOf(eco model.Ecosystem, name, version string) Input {
	p := &model.Package{ID: model.MustPackageVersion(eco, name, version)}
	m := &model.Manifest{Path: "requirements.txt", Ecosystem: eco, Kind: model.ManifestKindLockfile}
	f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "t"}, m.Path, p, finding.Key{})
	return NewInput(&f, p, m, now)
}

func TestPackageFunctions(t *testing.T) {
	dateutil := inputOf(model.EcosystemPyPI, "python.dateutil", "2.9.0")
	cases := []struct {
		name string
		expr string
		in   Input
		want bool
	}{
		{name: "is folds the name", expr: `package.is("python-dateutil")`, in: dateutil, want: true},
		{name: "a plain compare does not fold", expr: `package.name == "python.dateutil"`, in: dateutil},
		{name: "the canonical name", expr: `package.name == "python-dateutil"`, in: dateutil, want: true},
		{name: "the raw name", expr: `package.raw_name == "python.dateutil"`, in: dateutil, want: true},
		{name: "is another package", expr: `package.is("dateutil")`, in: dateutil},
		{name: "npm keeps case", expr: `package.is("jsonstream")`, in: inputOf(model.EcosystemNpm, "JSONStream", "1.0.3")},
		{name: "version below", expr: `package.version_cmp("2.10.0") < 0`, in: dateutil, want: true},
		{name: "version equal in another spelling", expr: `package.version_cmp("2.9") == 0`, in: dateutil, want: true},
		{name: "a release after its candidate", expr: `package.version_cmp("1.0rc1") > 0`, in: inputOf(model.EcosystemPyPI, "x", "1.0"), want: true},
		{name: "no order does not match", expr: `package.version_cmp("v4") < 0`, in: inputOf(model.EcosystemGitHubActions, "actions/checkout", "v3")},
		{name: "no order negated does not match", expr: `!(package.version_cmp("v4") < 0)`, in: inputOf(model.EcosystemGitHubActions, "actions/checkout", "v3")},
		{name: "no order with a false side does not match", expr: `package.version_cmp("v4") < 0 && true`, in: inputOf(model.EcosystemGitHubActions, "actions/checkout", "v3")},
		{name: "no order with a true side matches", expr: `package.version_cmp("v4") < 0 || package.is("actions/checkout")`, in: inputOf(model.EcosystemGitHubActions, "actions/checkout", "v3"), want: true},
		{name: "no package", expr: `package.is("x")`, in: Input{Finding: FindingInput{ControlID: "unpinned-action"}}},
		{name: "no package has no version", expr: `package.version_cmp("1.0") < 0`, in: Input{Finding: FindingInput{ControlID: "unpinned-action"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Compile(tc.expr)
			require.NoError(t, err)
			got, err := e.Match(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

package overview

import (
	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// Upgrade is the version of one package that fixes its findings.
type Upgrade struct {
	// Name is the raw name of the package in its first finding.
	Name string
	// From is the version in use of the first finding, and To the
	// highest version that a finding names.
	From, To model.PackageVersion
	// Latest reports that To is the latest version of the package, because
	// the finding that names it has no fixed version.
	Latest   bool
	Findings []*finding.Finding
}

// Upgrades puts the findings that an upgrade fixes together by package name,
// in the order of their first finding. A package with many findings takes
// the highest version. A vulnerability with no fixed version takes the
// latest version of the package, as its remediation does. A finding with no
// version above the one in use, or in an ecosystem with no version order,
// is in no upgrade.
func Upgrades(fs []*finding.Finding, latest map[model.PackageKey]string) []Upgrade {
	var out []Upgrade
	at := map[model.PackageKey]int{}
	for _, f := range fs {
		from, to, isLatest, ok := upgrade(f, latest)
		if !ok {
			continue
		}
		i, seen := at[from.NameKey()]
		if !seen {
			i = len(out)
			at[from.NameKey()] = i
			out = append(out, Upgrade{Name: from.RawName(), From: from})
		}
		u := &out[i]
		if u.To.IsZero() || less(u.To, to) {
			u.To, u.Latest = to, isLatest
		}
		u.Findings = append(u.Findings, f)
	}
	return out
}

// upgrade returns the package of a finding, the version that fixes it, and
// whether that version is the latest version.
func upgrade(f *finding.Finding, latest map[model.PackageKey]string) (model.PackageVersion, model.PackageVersion, bool, bool) {
	p := f.Subject.Package
	if p == nil || f.Remediation == nil {
		return model.PackageVersion{}, model.PackageVersion{}, false, false
	}
	id, err := p.PackageVersion()
	if err != nil {
		return model.PackageVersion{}, model.PackageVersion{}, false, false
	}
	version, isLatest := f.Remediation.FixedVersion, false
	if version == "" && f.Family == finding.FamilyVulnerability {
		version, isLatest = latest[id.Key()], true
	}
	if version == "" || !less(id, id.WithVersion(version)) {
		return model.PackageVersion{}, model.PackageVersion{}, false, false
	}
	return id, id.WithVersion(version), isLatest, true
}

// less reports a version below another under the order of the ecosystem.
func less(a, b model.PackageVersion) bool {
	c, err := a.Compare(b)
	return err == nil && c < 0
}

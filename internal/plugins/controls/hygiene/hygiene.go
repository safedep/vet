// Package hygiene holds the dependency hygiene controls (control catalog,
// phase 2): install scripts in a new dependency, provenance lost on an
// upgrade, a deprecated package, a license change on an upgrade, a
// dependency that is not on a registry, and a low OpenSSF Scorecard.
package hygiene

import (
	"context"
	"fmt"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/spdxlicense"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "hygiene"

// Control ids.
const (
	IDInstallScripts = "install-scripts-added"
	IDProvenanceLost = "provenance-lost"
	IDDeprecated     = "deprecated-package"
	IDLicenseChange  = "license-change"
	IDRelicensed     = "license-relicensed"
	IDNonRegistry    = "non-registry-dependency"
	IDScorecardLow   = "scorecard-low"
)

// defaultMinScore is the OpenSSF Scorecard score under which vet shows a
// package.
const defaultMinScore = 3.0

// Options are plugins.hygiene.options.
type Options struct {
	// MinScorecard is the OpenSSF Scorecard score under which vet shows a
	// package. The default is 3.
	MinScorecard *float64 `json:"min_scorecard"`
}

// Control evaluates the hygiene of the packages of a manifest.
type Control struct {
	minScore float64
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	c := &Control{minScore: defaultMinScore}
	if o.MinScorecard != nil {
		if *o.MinScorecard < 0 || *o.MinScorecard > 10 {
			return nil, fmt.Errorf("hygiene: min_scorecard %v is not between 0 and 10", *o.MinScorecard)
		}
		c.minScore = *o.MinScorecard
	}
	return c, nil
}

var infos = []plugin.ControlInfo{
	{
		ID: IDInstallScripts, Family: finding.FamilyHygiene, Severity: finding.SeverityHigh,
		Title:       "New dependency with install scripts",
		Description: "The change adds or upgrades a package that runs a preinstall, install or postinstall script. The script runs on each machine that installs the package.",
	},
	{
		ID: IDProvenanceLost, Family: finding.FamilyHygiene, Severity: finding.SeverityMedium,
		Title:       "Provenance lost on an upgrade",
		Description: "The previous version has a SLSA provenance attestation and the new version has none. The new version may not come from the build system of the project.",
	},
	{
		ID: IDDeprecated, Family: finding.FamilyHygiene, Severity: finding.SeverityMedium,
		Title:       "Deprecated package",
		Description: "The registry marks the package version deprecated. It gets no fixes.",
	},
	{
		ID: IDLicenseChange, Family: finding.FamilyLicense, Severity: finding.SeverityMedium,
		Title:       "License change on an upgrade",
		Description: "The new version has a license other than the license of the previous version.",
	},
	{
		ID: IDRelicensed, Family: finding.FamilyLicense, Severity: finding.SeverityHigh,
		Title:       "Relicensed to a license that limits use",
		Description: "The new version moves to a license that limits the use of the code (source available, no commercial use or no derived works, such as SSPL-1.0, BUSL-1.1 or CC-BY-NC-4.0), or to no license.",
	},
	{
		ID: IDNonRegistry, Family: finding.FamilyHygiene, Severity: finding.SeverityMedium,
		Title:       "Dependency that is not on a registry",
		Description: "A dependency comes from git, a URL or a file path, or takes any version. No registry checks it, and it can change with no new version.",
	},
	{
		ID: IDScorecardLow, Family: finding.FamilyHygiene, Severity: finding.SeverityInfo,
		Title:       "Low OpenSSF Scorecard",
		Description: "The source repository of the package has a low OpenSSF Scorecard score. vet shows it for review.",
	},
}

// Controls describes the control ids.
func (*Control) Controls() []plugin.ControlInfo { return infos }

// OptionsSchema returns the JSON Schema of the options.
func (*Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Evaluate checks the packages of the manifest, and reads the manifest
// file for the dependencies that are not on a registry.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	scripts, err := installScripts(m)
	if err != nil {
		return nil, err
	}
	for _, p := range m.Packages {
		if p.Change == model.ChangeRemoved {
			continue
		}
		if scripts[p.ID.Key()] && introduces(p) {
			out = append(out, packageFinding(IDInstallScripts, m, p, "",
				fmt.Sprintf("%s runs install scripts", p.ID),
				"Check what the scripts do. Install with --ignore-scripts if the package works with no script."))
		}
		out = append(out, c.insight(m, p)...)
		if src := nonRegistrySource(p.Resolved); src != "" {
			out = append(out, packageFinding(IDNonRegistry, m, p, src,
				fmt.Sprintf("%s comes from %s", p.ID.RawName(), src),
				"Use a released version from a registry, or pin the source to a commit."))
		}
	}
	files, err := declaredNonRegistry(m)
	if err != nil {
		return nil, err
	}
	return append(out, files...), nil
}

func introduces(p *model.Package) bool {
	return p.Change == model.ChangeAdded || p.Change == model.ChangeUpgraded || p.Change == model.ChangeDowngraded
}

func (c *Control) insight(m *model.Manifest, p *model.Package) []finding.Finding {
	in, prev := p.Insight, p.PreviousInsight
	if in == nil {
		return nil
	}
	var out []finding.Finding
	// gap G5: Insights v2 has no archived flag for the source repository,
	// so the control reports deprecation only.
	if in.Deprecated {
		out = append(out, packageFinding(IDDeprecated, m, p, "",
			fmt.Sprintf("%s is deprecated", p.ID),
			"Move to a maintained version or to another package."))
	}
	if prev != nil && prev.Provenance && !in.Provenance {
		out = append(out, packageFinding(IDProvenanceLost, m, p, p.PreviousVersion,
			fmt.Sprintf("%s has no provenance, and %s had one", p.ID, p.PreviousVersion),
			"Check that the maintainers published the version from their build system, or stay on the previous version."))
	}
	if prev != nil && len(prev.Licenses) > 0 && len(in.Licenses) > 0 && !spdxlicense.Equal(prev.Licenses, in.Licenses) {
		out = append(out, licenseChange(m, p))
	}
	if sc := in.Scorecard; sc != nil && sc.Score < c.minScore {
		out = append(out, packageFinding(IDScorecardLow, m, p, "",
			fmt.Sprintf("%s has an OpenSSF Scorecard score of %.1f", p.ID.RawName(), sc.Score),
			"Review the maintenance and the security practices of the project."))
	}
	return out
}

// licenseChange reports a license change. A move from a license that does
// not limit the use of the code to one that does, or to NONE, is a relicense.
func licenseChange(m *model.Manifest, p *model.Package) finding.Finding {
	from, to := strings.Join(p.PreviousInsight.Licenses, ", "), strings.Join(p.Insight.Licenses, ", ")
	discriminator := strings.Join(p.Insight.Licenses, ",")
	if relicensed(spdxlicense.Parse(p.PreviousInsight.Licenses), spdxlicense.Parse(p.Insight.Licenses)) {
		return packageFinding(IDRelicensed, m, p, discriminator,
			fmt.Sprintf("%s changes its license from %s to %s, which limits the use of the code", p.ID.RawName(), from, to),
			"Read the new license before the upgrade. Stay on the previous version, or replace the package, if the license does not fit the project.")
	}
	return packageFinding(IDLicenseChange, m, p, discriminator,
		fmt.Sprintf("%s changes its license from %s to %s", p.ID.RawName(), from, to),
		"Check that the new license fits the license policy of the project.")
}

func relicensed(prev, next spdxlicense.Declared) bool {
	if !prev.Known() || prev.NoLicense() || spdxlicense.Restricted(prev) {
		return false
	}
	return next.NoLicense() || spdxlicense.Restricted(next)
}

func packageFinding(id string, m *model.Manifest, p *model.Package, discriminator, title, fix string) finding.Finding {
	var info plugin.ControlInfo
	for _, i := range infos {
		if i.ID == id {
			info = i
		}
	}
	f := finding.ForPackage(finding.Meta{
		ControlID: id, Family: info.Family, Severity: info.Severity, Confidence: finding.ConfidenceHigh,
		Title: title, Description: info.Description,
	}, m.Path, p, finding.Key{Discriminator: discriminator})
	f.Remediation = &finding.Remediation{Summary: fix}
	return f
}

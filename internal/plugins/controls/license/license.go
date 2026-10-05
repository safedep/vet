// Package license holds the license control. It checks the license of each
// package, as an SPDX license expression, against the allow and deny lists
// of its options. With no list, it reports nothing.
package license

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/spdxlicense"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "license"

// Control ids.
const (
	IDDenied     = "license-denied"
	IDNotAllowed = "license-not-allowed"
	IDUnknown    = "license-unknown"
)

// The values of the unknown option.
const (
	UnknownReport = "report"
	UnknownIgnore = "ignore"
)

// The values of the scope option.
const (
	ScopeAll     = "all"
	ScopeRuntime = "runtime"
	ScopeDirect  = "direct"
)

// Options are plugins.license.options.
type Options struct {
	// Allow lists the licenses that a package can have: SPDX license ids,
	// "id WITH exception" terms, LicenseRef ids, or the sets osi-approved,
	// fsf-libre and osi-approved-or-fsf-libre. A package passes when the
	// list satisfies its license expression.
	Allow []string `json:"allow"`
	// Deny lists the licenses that a package cannot have, with the same
	// entries as Allow. A package fails when each choice of its license
	// expression has a denied license.
	Deny []string `json:"deny"`
	// Unknown is "report" or "ignore" for a package with no license data, a
	// license that is not an SPDX expression, or NONE when only Deny is set.
	// The default is report.
	Unknown string `json:"unknown" jsonschema:"enum=report,enum=ignore"`
	// Scope selects the packages to check: "all" (the default), "runtime"
	// to skip dev dependencies, or "direct" for the direct dependencies. A
	// manifest that marks no package direct has all its packages checked.
	Scope string `json:"scope" jsonschema:"enum=all,enum=runtime,enum=direct"`
}

// Control checks the license of the packages of a manifest.
type Control struct {
	policy        *spdxlicense.Policy
	reportUnknown bool
	scope         string
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	policy, err := spdxlicense.NewPolicy(o.Allow, o.Deny)
	if err != nil {
		return nil, fmt.Errorf("license: %w", err)
	}
	c := &Control{policy: policy, scope: cmp.Or(o.Scope, ScopeAll)}
	switch o.Unknown {
	case "", UnknownReport:
		c.reportUnknown = true
	case UnknownIgnore:
	default:
		return nil, fmt.Errorf("license: unknown %q: use report or ignore", o.Unknown)
	}
	switch c.scope {
	case ScopeAll, ScopeRuntime, ScopeDirect:
	default:
		return nil, fmt.Errorf("license: scope %q: use all, runtime or direct", o.Scope)
	}
	return c, nil
}

var infos = []plugin.ControlInfo{
	{
		ID: IDDenied, Family: finding.FamilyLicense, Severity: finding.SeverityHigh,
		Title:       "Denied license",
		Description: "Each choice of the license of the package has a license that plugins.license.options.deny names.",
	},
	{
		ID: IDNotAllowed, Family: finding.FamilyLicense, Severity: finding.SeverityMedium,
		Title:       "License not in the allow list",
		Description: "The licenses that plugins.license.options.allow names do not satisfy the license of the package.",
	},
	{
		ID: IDUnknown, Family: finding.FamilyLicense, Severity: finding.SeverityLow,
		Title:       "Unknown license",
		Description: "The package has no license data, a license that is not an SPDX license expression, or no license (NONE) with only a deny list. The lists cannot decide it.",
	},
}

// Controls describes the control ids.
func (*Control) Controls() []plugin.ControlInfo { return infos }

// OptionsSchema returns the JSON Schema of the options.
func (*Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Evaluate checks each package of the manifest. A package with no insight
// has no verdict: its ecosystem has no license data, or the lookup failed
// and the scan records a diagnostic.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	if !c.policy.Allows() && !c.policy.Denies() {
		return nil, nil
	}
	var out []finding.Finding
	inScope := c.inScope(m)
	for _, p := range m.Packages {
		if p.Change == model.ChangeRemoved || p.Insight == nil || !inScope(p) {
			continue
		}
		d := spdxlicense.Parse(p.Insight.Licenses)
		if f, ok := c.finding(m, p, d, c.policy.Check(d)); ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// inScope returns the scope test for the packages of a manifest. When the
// manifest marks no package direct, vet does not know the direct packages,
// so it checks all of them.
func (c *Control) inScope(m *model.Manifest) func(*model.Package) bool {
	switch c.scope {
	case ScopeRuntime:
		return func(p *model.Package) bool { return !p.Dev }
	case ScopeDirect:
		if slices.ContainsFunc(m.Packages, func(p *model.Package) bool { return p.Direct && p.Change != model.ChangeRemoved }) {
			return func(p *model.Package) bool { return p.Direct }
		}
	}
	return func(*model.Package) bool { return true }
}

func (c *Control) finding(m *model.Manifest, p *model.Package, d spdxlicense.Declared, r spdxlicense.Result) (finding.Finding, bool) {
	shown := strings.Join(p.Insight.Licenses, ", ")
	var id, title, fix string
	switch r.Verdict {
	case spdxlicense.Denied:
		id = IDDenied
		title = fmt.Sprintf("%s has the denied license %s", p.ID, strings.Join(r.Denied, ", "))
		fix = "Replace the package, or add a suppression with the reason that the license is acceptable."
	case spdxlicense.NotAllowed:
		id = IDNotAllowed
		title = fmt.Sprintf("The allow list does not have the license %s of %s", licenseText(d, shown), p.ID)
		fix = "Replace the package, or add the license to plugins.license.options.allow after a legal review."
	case spdxlicense.Unknown:
		if !c.reportUnknown {
			return finding.Finding{}, false
		}
		id = IDUnknown
		switch {
		case d.NoLicense():
			title = fmt.Sprintf("%s declares no license, so the author keeps all rights", p.ID)
		case shown != "":
			title = fmt.Sprintf("%s has the license %q, which is not an SPDX expression", p.ID, shown)
		default:
			title = fmt.Sprintf("%s has no license data", p.ID)
		}
		fix = "Read the license of the package, then add a suppression with the license as the reason."
	default:
		return finding.Finding{}, false
	}
	info := infoOf(id)
	f := finding.ForPackage(finding.Meta{
		ControlID: id, Family: info.Family, Severity: info.Severity, Confidence: finding.ConfidenceHigh,
		Title: title, Description: info.Description,
	}, m.Path, p, finding.Key{Discriminator: shown})
	declared := fmt.Sprintf("The declared license is %s.", cmp.Or(shown, "not known"))
	if d.Expression != "" && d.Expression != shown {
		declared = fmt.Sprintf("The declared license is %s, and its SPDX form is %s.", shown, d.Expression)
	}
	f.Evidence = []finding.Evidence{{
		Source:  "insights",
		Summary: fmt.Sprintf("%s vet checks it with the SPDX License List %s.", declared, spdxlicense.ListVersion()),
	}}
	f.Remediation = &finding.Remediation{Summary: fix}
	return f, true
}

// licenseText is the SPDX expression of a license, or the declared text when
// no expression parses.
func licenseText(d spdxlicense.Declared, shown string) string {
	if d.Expression != "" {
		return d.Expression
	}
	return shown
}

func infoOf(id string) plugin.ControlInfo {
	for _, i := range infos {
		if i.ID == id {
			return i
		}
	}
	return plugin.ControlInfo{}
}

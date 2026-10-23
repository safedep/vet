// Package cooldown is the dependency cooldown control. It reports a
// package version that its registry published inside the cooldown window.
package cooldown

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the control id.
const Name = "dependency-cooldown"

// DefaultDays is the cooldown window. It is the default of pmg.
const DefaultDays = 2

// DaysKey is the config key of the window.
const DaysKey = "plugins." + Name + ".options.days"

// Options are plugins.dependency-cooldown.options.
type Options struct {
	Days *int `json:"days"`
	// Skip lists the packages that the cooldown does not check, such as
	// the SDKs of your own organization. Other controls still check them.
	Skip []Skip `json:"skip"`
}

// Skip is one package that the cooldown does not check. A PURL with no
// version skips each version. A name with *, ? or [ is a glob.
type Skip struct {
	PURL   string `json:"purl"`
	Reason string `json:"reason"`
}

// Control reports the versions inside the cooldown window.
type Control struct {
	days int
	// source names the setting of the window, as "flag --cooldown-days",
	// or "" for the default.
	source string
	skip   []model.PackagePattern
	now    func() time.Time
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	c := &Control{days: DefaultDays, now: time.Now}
	if o.Days != nil {
		if *o.Days < 1 {
			return nil, fmt.Errorf("dependency-cooldown: days must be 1 or more, got %d", *o.Days)
		}
		c.days = *o.Days
		c.source = "your config"
		if or, ok := cfg.(plugin.Originer); ok {
			c.source = cmp.Or(or.Origin("days"), c.source)
		}
	}
	for i, s := range o.Skip {
		if s.Reason == "" {
			return nil, fmt.Errorf("dependency-cooldown: skip[%d]: reason is empty", i)
		}
		p, err := model.ParsePackagePattern(s.PURL)
		if err != nil {
			return nil, fmt.Errorf("dependency-cooldown: skip[%d]: %w", i, err)
		}
		c.skip = append(c.skip, p)
	}
	return c, nil
}

// Controls describes the control id.
func (c *Control) Controls() []plugin.ControlInfo {
	return []plugin.ControlInfo{{
		ID: Name, Family: finding.FamilyCooldown, Severity: finding.SeverityHigh,
		Title:       "Version inside the cooldown window",
		Description: "The registry published the version less than the cooldown window ago. Most malicious versions are found and removed in the first days.",
	}}
}

// Evaluate reports each package of the manifest that the registry
// published inside the window. It uses the same predicate as pmg:
// floor(days since publish) < window.
//
// A package with no publish date gets no check. The enricher diagnostic
// reports a backend that did not answer. A package that Insights v2 does
// not know, such as a private package, gets no check and no diagnostic.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	now := c.now().UTC()
	var out []finding.Finding
	for _, p := range m.Packages {
		if p.Insight == nil || p.Insight.PublishedAt == nil || c.skipped(p.ID) {
			continue
		}
		published := p.Insight.PublishedAt.UTC()
		days := int(now.Sub(published).Hours() / 24)
		if days >= c.days {
			continue
		}
		out = append(out, c.finding(m, p, published, days))
	}
	return out, nil
}

func (c *Control) skipped(id model.PackageVersion) bool {
	for _, p := range c.skip {
		if p.Matches(id) {
			return true
		}
	}
	return false
}

func (c *Control) finding(m *model.Manifest, p *model.Package, published time.Time, days int) finding.Finding {
	eligible := published.AddDate(0, 0, c.days)
	f := finding.ForPackage(finding.Meta{
		ControlID: Name, Family: finding.FamilyCooldown, Severity: finding.SeverityHigh,
		Title: "Published " + ago(days),
		Description: fmt.Sprintf("The registry published this version on %s. The cooldown is %s (%s). The version can merge after %s.",
			humanize.Minute(published), humanize.Count(c.days, "day"), c.sourceText(), humanize.MinuteAfter(eligible)),
	}, m.Path, p, finding.Key{})
	f.Evidence = []finding.Evidence{{Source: "insights", Summary: "published at " + published.Format(time.RFC3339)}}
	f.Remediation = &finding.Remediation{Summary: keep(p), WaitUntil: &eligible}
	if d := p.Declared; d != nil {
		f.Locus = &finding.Locus{Path: d.Path, StartLine: d.Line}
	}
	return f
}

// keep is the fix that does not wait: keep the version of before. The
// other fix is to wait until Remediation.WaitUntil, and each format shows
// that time. A package that a field of a project file declares, as pnpm in
// "packageManager", is kept in that field.
//
// The text does not name the package, so the packages of one release, as
// esbuild and its platform packages, share one fix and show as one cause.
// Two unrelated upgrades of one lockfile from the same version also share
// it. The report has no parent of a package that would tell them apart.
func keep(p *model.Package) string {
	switch d := p.Declared; {
	case d != nil && p.PreviousVersion != "":
		return fmt.Sprintf("Keep %q at %s@%s in %s.", d.Field, d.Package, p.PreviousVersion, d.Path)
	case d != nil:
		return fmt.Sprintf("Set %q in %s to a version older than the cooldown.", d.Field, d.Path)
	case p.PreviousVersion != "":
		return fmt.Sprintf("Keep version %s.", p.PreviousVersion)
	}
	return "Pick a version older than the cooldown."
}

// sourceText says where the window comes from.
func (c *Control) sourceText() string { return cmp.Or(c.source, "vet default") }

func ago(days int) string {
	switch {
	case days < 1:
		return "less than 1 day ago"
	case days == 1:
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

// OptionsSchema returns the JSON Schema of the options.
func (c *Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var (
	_ plugin.Control   = (*Control)(nil)
	_ plugin.Describer = (*Control)(nil)
	_ plugin.Schemer   = (*Control)(nil)
)

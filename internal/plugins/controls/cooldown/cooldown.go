// Package cooldown is the dependency cooldown control. It reports a
// package version that its registry published inside the cooldown window.
package cooldown

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the control id.
const Name = "dependency-cooldown"

// DefaultDays is the cooldown window of pmg.
const DefaultDays = 5

// Options are plugins.dependency-cooldown.options.
type Options struct {
	Days *int `json:"days"`
}

// Control reports the versions inside the cooldown window.
type Control struct {
	days int
	now  func() time.Time
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
		if p.Insight == nil || p.Insight.PublishedAt == nil {
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

func (c *Control) finding(m *model.Manifest, p *model.Package, published time.Time, days int) finding.Finding {
	eligible := published.AddDate(0, 0, c.days)
	f := finding.ForPackage(finding.Meta{
		ControlID: Name, Family: finding.FamilyCooldown, Severity: finding.SeverityHigh,
		Title:       fmt.Sprintf("%s was published %s", p.ID, ago(days)),
		Description: fmt.Sprintf("The registry published this version on %s. The cooldown window is %d days, so the version is eligible on %s.", published.Format(time.DateOnly), c.days, eligible.Format(time.DateOnly)),
	}, m.Path, p, finding.Key{})
	f.Evidence = []finding.Evidence{{Source: "insights", Summary: "published at " + published.Format(time.RFC3339)}}
	summary := fmt.Sprintf("Wait until %s, or keep the version that you used before.", eligible.Format(time.DateOnly))
	if p.PreviousVersion != "" {
		summary = fmt.Sprintf("Wait until %s, or keep version %s.", eligible.Format(time.DateOnly), p.PreviousVersion)
	}
	f.Remediation = &finding.Remediation{Summary: summary}
	return f
}

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

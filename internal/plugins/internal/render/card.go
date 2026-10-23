package render

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/weburl"
)

const (
	// MaxField bounds a name, a title or a path, and MaxText a description,
	// so that no single finding fills a markdown report.
	MaxField = 200
	MaxText  = 1000
	// maxMembers bounds the names in the list of a card.
	maxMembers = 50
)

// Bounded escapes free text for markdown and bounds it to n runes.
func Bounded(s string, n int) string { return Markdown(Truncate(s, n)) }

// ShortCode puts a name or a path in a code span, bounded to MaxField runes.
func ShortCode(s string) string { return Code(Truncate(s, MaxField)) }

// Kind is the label of a finding in a markdown report: its severity, or
// "cooldown" for a version that waits for its cooldown. The report keeps
// the severity of a cooldown finding, but "high" reads as a high risk.
func Kind(f *finding.Finding) string {
	if f.Family == finding.FamilyCooldown {
		return "cooldown"
	}
	return string(f.Severity)
}

// More counts the findings of a group after its lead, as " and 14 more".
func (g Group) More() string {
	if n := len(g.Findings) - 1; n > 0 {
		return fmt.Sprintf(" and %d more", n)
	}
	return ""
}

// Fix is the fix of the lead, with the end of the wait of the group, or "".
func (g Group) Fix() string {
	r := g.Lead().Remediation
	if r == nil || r.Summary == "" {
		return ""
	}
	fix := Text(r.Summary)
	if until, ok := g.WaitUntil(); ok {
		fix += " Or wait until " + humanize.MinuteAfter(until) + ", then run the job again."
	}
	return fix
}

// Reach is the riskiest reach of the group, so a called vulnerability is
// never hidden behind one that is not called.
func (g Group) Reach() *finding.Reach { return TopReach(g.Findings) }

// TopReach is the riskiest reach of the findings, or nil.
func TopReach(fs []*finding.Finding) *finding.Reach {
	var top *finding.Reach
	for _, f := range fs {
		if f.Reach != nil && (top == nil || f.Reach.Level.Rank() > top.Level.Rank()) {
			top = f.Reach
		}
	}
	return top
}

// Card is the markdown of a group that each markdown format shows. Each
// part is escaped and bounded, and is "" when the group has none.
type Card struct {
	// Head names the lead: the subject, the count of the other findings,
	// the title and the kind. The format adds the place.
	Head string
	// Body is the paragraphs of the lead: the description, the gate and
	// its help, the fix, the command, the evidence and the reach.
	Body []string
	// Members lists the other findings of the group, one line each.
	Members []string
}

// NewCard builds the card of a group.
func NewCard(g Group) Card {
	f := g.Lead()
	c := Card{Head: fmt.Sprintf("%s%s: **%s** · %s", ShortCode(Subject(f)), g.More(), Bounded(Title(f), MaxField), ShortCode(Kind(f)))}
	add := func(format string, args ...any) { c.Body = append(c.Body, fmt.Sprintf(format, args...)) }
	if f.Description != "" {
		add("%s", Bounded(Text(f.Description), MaxText))
	}
	if gr := f.Gate; gr != nil {
		add("**%s:** %s", gr.Label(), Bounded(Text(gr.Cause()), MaxField))
		var help []string
		if gr.Help != "" && (f.Remediation == nil || gr.Help != f.Remediation.Summary) {
			help = append(help, Bounded(Text(gr.Help), MaxText))
		}
		if u := SafeURL(gr.Link); u != "" {
			help = append(help, fmt.Sprintf("[Policy guidance](%s)", u))
		}
		if len(help) > 0 {
			add("**Policy help:** %s", strings.Join(help, " · "))
		}
	}
	if fix := g.Fix(); fix != "" {
		add("**Fix:** %s", Bounded(fix, MaxText))
	}
	if r := f.Remediation; r != nil && r.Command != "" {
		add("```sh\n%s\n```", strings.ReplaceAll(Truncate(Text(r.Command), MaxText), "```", "'''"))
	}
	if len(f.Evidence) > 0 {
		add("**Evidence:** %s", Bounded(Text(f.Evidence[0].Summary), MaxText))
	}
	if r := g.Reach(); r != nil {
		add("**Reach:** %s", Bounded(r.Label(), MaxField))
	}
	title := Title(f)
	for i, m := range g.Findings[1:] {
		if i == maxMembers {
			c.Members = append(c.Members, fmt.Sprintf("- %d more in the full report", len(g.Findings)-1-maxMembers))
			break
		}
		line := "- " + ShortCode(Subject(m))
		if t := Title(m); t != title {
			line += ": " + Bounded(t, MaxField)
		}
		c.Members = append(c.Members, line)
	}
	return c
}

// SafeURL returns an http or https link that is safe in a markdown link
// target, or "". The policy validates the link. A report file can come
// from anywhere, so a format checks it again.
func SafeURL(s string) string {
	if !weburl.Valid(s) {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", `\`, "%5C", "<", "%3C", ">", "%3E", `"`, "%22").Replace(u.String())
}

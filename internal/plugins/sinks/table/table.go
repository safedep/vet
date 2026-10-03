// Package table is the table format, the default in rich mode: the count
// cards, the most severe findings and the AI and crypto capabilities. The step lines and the gate line go
// to stderr, so the table is the data part of the scan view.
package table

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/internal/tui/stat"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/internal/tui/table"
	"github.com/safedep/vet/v2/internal/tui/theme"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "table"

// DefaultLimit is the number of findings that the table shows.
const DefaultLimit = 10

// Options are the options of the table format.
type Options struct {
	// All shows every finding.
	All bool `json:"all"`
	// Limit is the number of findings to show. Zero means DefaultLimit.
	Limit int `json:"limit"`
}

// Sink writes the table format.
type Sink struct {
	limit int
}

// New builds the sink from its options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	s := Sink{limit: DefaultLimit}
	switch {
	case o.All:
		s.limit = 0
	case o.Limit < 0:
		return nil, fmt.Errorf("table: limit must be 0 or more, got %d", o.Limit)
	case o.Limit > 0:
		s.limit = o.Limit
	}
	return s, nil
}

// Write writes the cards and the findings table.
func (s Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	h, t := r.Header(), r.Trailer()
	delta := h.Scan.Mode == report.ScanModeDelta

	headers := []string{"SEVERITY", "CONTROL"}
	if delta {
		headers = append(headers, "CHANGE")
	}
	headers = append(headers, "SUBJECT", "WHERE")
	tbl := table.New().Headers(headers...)
	shown, more := 0, 0
	err := render.EachFinding(ctx, r, func(f *finding.Finding) error {
		if f.Suppressed() {
			return nil
		}
		if s.limit > 0 && shown == s.limit {
			more++
			return nil
		}
		shown++
		row := []string{badge(f.Severity), render.Text(f.ControlID)}
		if delta {
			row = append(row, strings.ToLower(string(f.Change)))
		}
		tbl.Row(append(row, render.Subject(f), render.Where(f))...)
		return nil
	})
	if err != nil {
		return err
	}

	caps, err := capabilities(ctx, r)
	if err != nil {
		return err
	}

	parts := []string{stat.Render(cards(t, caps)...)}
	if shown == 0 {
		checked := "1 package"
		if n := t.Summary.Packages; n != 1 {
			checked = fmt.Sprintf("%d packages", n)
		}
		parts = append(parts, style.Success("No findings. "+checked+" checked."))
	} else {
		parts = append(parts, tbl.Render())
	}
	if more > 0 {
		parts = append(parts, section.Hint(fmt.Sprintf("%d more (vet report show -o table --all)", more)))
	}
	if n := t.Summary.Suppressed; n > 0 {
		parts = append(parts, section.Hint(fmt.Sprintf("%d suppressed (vet report show -o json)", n)))
	}
	if len(caps) > 0 {
		parts = append(parts, s.capabilityTable(caps, delta)...)
	}
	_, err = io.WriteString(w, section.Join(parts...)+"\n")
	return err
}

// capabilities returns the capabilities of the report in reader order.
func capabilities(ctx context.Context, r plugin.Report) ([]*report.Capability, error) {
	var out []*report.Capability
	for c, err := range r.Capabilities(ctx) {
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	slices.SortStableFunc(out, report.CompareCapabilities)
	return out, nil
}

// capabilityTable renders the AI and crypto section: one row for each
// capability, with the first call site.
func (s Sink) capabilityTable(caps []*report.Capability, delta bool) []string {
	headers := []string{"KIND"}
	if delta {
		headers = append(headers, "CHANGE")
	}
	tbl := table.New().Headers(append(headers, "CAPABILITY", "TAGS", "WHERE")...)
	shown := caps
	if s.limit > 0 && len(shown) > s.limit {
		shown = shown[:s.limit]
	}
	for _, c := range shown {
		row := []string{strings.ToUpper(string(c.Kind()))}
		if delta {
			row = append(row, strings.ToLower(string(c.Change)))
		}
		tbl.Row(append(row, render.Truncate(render.Text(c.Name()), 40), tags(c), CapabilityWhere(c))...)
	}
	parts := []string{style.Heading("AI and crypto"), tbl.Render()}
	if more := len(caps) - len(shown); more > 0 {
		parts = append(parts, section.Hint(fmt.Sprintf("%d more (vet report capability list)", more)))
	}
	return parts
}

// CapabilityWhere is file:line of the first call site, with the count of
// the other call sites.
func CapabilityWhere(c *report.Capability) string {
	if len(c.Occurrences) == 0 {
		return ""
	}
	o := c.Occurrences[0]
	where := render.Text(o.File)
	if o.Line > 0 {
		where = fmt.Sprintf("%s:%d", where, o.Line)
	}
	if n := len(c.Occurrences) - 1; n > 0 {
		where = fmt.Sprintf("%s (+%d)", where, n)
	}
	return where
}

// tags lists the tags other than the kind tag. The weak tag is a warning
// badge, as a severity is.
func tags(c *report.Capability) string {
	var out []string
	for _, t := range c.Tags {
		switch t {
		case report.TagAI, report.TagCrypto:
		case report.TagWeak:
			out = append(out, style.Badge(theme.RoleWarning, strings.ToUpper(t)))
		default:
			out = append(out, render.Text(t))
		}
	}
	return strings.Join(out, ", ")
}

func cards(t *report.Trailer, caps []*report.Capability) []stat.Card {
	sum := t.Summary
	crit, high := theme.RoleError, theme.RoleWarning
	cs := []stat.Card{
		{Label: "Packages", Value: strconv.Itoa(sum.Packages)},
		{Label: "Findings", Value: strconv.Itoa(sum.Findings)},
		{Label: "Critical", Value: strconv.Itoa(sum.BySeverity[finding.SeverityCritical]), Accent: &crit},
		{Label: "High", Value: strconv.Itoa(sum.BySeverity[finding.SeverityHigh]), Accent: &high},
	}
	var ai, crypto int
	for _, c := range caps {
		switch c.Kind() {
		case report.CapabilityAI:
			ai++
		case report.CapabilityCrypto:
			crypto++
		}
	}
	if ai > 0 {
		cs = append(cs, stat.Card{Label: "AI", Value: strconv.Itoa(ai)})
	}
	if crypto > 0 {
		cs = append(cs, stat.Card{Label: "Crypto", Value: strconv.Itoa(crypto)})
	}
	switch t.Gate.Outcome {
	case report.GatePass:
		pass := theme.RoleSuccess
		cs = append(cs, stat.Card{Label: "Gate", Value: "PASS", Accent: &pass})
	case report.GateFail:
		cs = append(cs, stat.Card{Label: "Gate", Value: "FAIL", Accent: &crit})
	}
	return cs
}

func badge(s finding.Severity) string {
	role := theme.RoleInfo
	switch s {
	case finding.SeverityCritical:
		role = theme.RoleError
	case finding.SeverityHigh, finding.SeverityMedium:
		role = theme.RoleWarning
	}
	return style.Badge(role, strings.ToUpper(string(s)))
}

// OptionsSchema returns the JSON Schema of the options.
func (s Sink) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var _ plugin.Schemer = Sink{}

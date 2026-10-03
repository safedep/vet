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

	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/semver"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/output"
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

// DefaultLimit is the number of rows that the table shows.
const DefaultLimit = 10

// wideWidth is the terminal width from which the findings table shows the
// CONTROL and WHERE columns, and the capability table the CALL column.
const wideWidth = 110

// minTextWidth is the narrowest FINDING column. When the other columns
// leave less room, the table also cuts them.
const minTextWidth = 16

// textLines is the most lines that the FINDING text of a row takes. A
// longer text ends with an ellipsis.
const textLines = 2

// Options are the options of the table format.
type Options struct {
	// All shows every finding on its own row, with no limit.
	All bool `json:"all"`
	// Limit is the number of rows to show. Zero means DefaultLimit.
	Limit int `json:"limit"`
}

// Sink writes the table format.
type Sink struct {
	all   bool
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
		s.all, s.limit = true, 0
	case o.Limit < 0:
		return nil, fmt.Errorf("table: limit must be 0 or more, got %d", o.Limit)
	case o.Limit > 0:
		s.limit = o.Limit
	}
	return s, nil
}

// row is one row of the findings table: one finding, or the vulnerability
// findings of one package. The first finding is the most severe.
type row []*finding.Finding

// Write writes the cards and the findings table.
func (s Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	h, t := r.Header(), r.Trailer()
	delta := h.Scan.Mode == report.ScanModeDelta
	if sum := t.Summary; sum.Manifests == 0 && sum.Packages == 0 && sum.Findings == 0 && sum.Capabilities == 0 {
		// A scan that read nothing has nothing to count. The scan view
		// warns that it found no manifest, so zero cards and "No
		// findings" do not read as a clean result.
		return nil
	}

	var open []*finding.Finding
	var ids []string
	err := render.EachFinding(ctx, r, func(f *finding.Finding) error {
		ids = append(ids, f.ID)
		if !f.Suppressed() {
			open = append(open, f)
		}
		return nil
	})
	if err != nil {
		return err
	}
	rows := s.rows(open)
	shown := rows
	if s.limit > 0 && len(shown) > s.limit {
		shown = shown[:s.limit]
	}

	caps, err := capabilities(ctx, r)
	if err != nil {
		return err
	}

	parts := []string{stat.Render(cards(t)...)}
	if len(shown) == 0 {
		parts = append(parts, style.Success("No findings. "+plural(t.Summary.Packages, "package", "packages")+" checked."))
	} else {
		parts = append(parts, findingTable(shown, report.ShortIDLength(ids), delta, output.Width()))
	}
	if hints := findingHints(len(open), rows, len(shown), t.Summary.Suppressed); len(hints) > 0 {
		parts = append(parts, strings.Join(hints, "\n"))
	}
	if len(caps) > 0 {
		parts = append(parts, s.capabilityTable(caps, delta)...)
	}
	_, err = io.WriteString(w, section.Join(parts...)+"\n")
	return err
}

// rows puts each finding on a row. With no --all, the vulnerability findings
// of one package in one manifest share a row.
func (s Sink) rows(fs []*finding.Finding) []row {
	var rows []row
	at := map[string]int{}
	for _, f := range fs {
		if p := f.Subject.Package; !s.all && p != nil && f.Family == finding.FamilyVulnerability {
			k := p.PURL + "\x00" + p.ManifestPath
			if i, ok := at[k]; ok {
				rows[i] = append(rows[i], f)
				continue
			}
			at[k] = len(rows)
		}
		rows = append(rows, row{f})
	}
	slices.SortStableFunc(rows, func(a, b row) int {
		return b[0].Severity.Rank() - a[0].Severity.Rank()
	})
	return rows
}

// findingTable drops CONTROL and WHERE on a narrow terminal. FINDING takes
// the width that the other columns leave, and wraps onto a second line, so
// that a cut falls on the FINDING text and not on the subject or the place.
func findingTable(rows []row, idLen int, delta bool, width int) string {
	wide := width >= wideWidth
	headers := []string{"SEVERITY", "ID"}
	if wide {
		headers = append(headers, "CONTROL")
	}
	if delta {
		headers = append(headers, "CHANGE")
	}
	headers = append(headers, "SUBJECT", "FINDING")
	textAt := len(headers) - 1
	if wide {
		headers = append(headers, "WHERE")
	}
	cells := [][]string{headers}
	for _, r := range rows {
		f := r[0]
		row := []string{badge(f.Severity), f.ID[:min(idLen, len(f.ID))]}
		if wide {
			row = append(row, render.Text(f.ControlID))
		}
		if delta {
			row = append(row, strings.ToLower(string(f.Change)))
		}
		row = append(row, render.Subject(f), "")
		if wide {
			row = append(row, render.Where(f))
		}
		cells = append(cells, row)
	}
	// Each column takes two cells of padding and one of border, and the
	// table one more border.
	room := width - 1 - 3
	for i := range headers {
		if i != textAt {
			room -= columnWidth(cells, i) + 3
		}
	}
	room = max(room, minTextWidth)
	tbl := table.New().Headers(headers...)
	for i, row := range cells[1:] {
		row[textAt] = wrap(rows[i].text(room), room, textLines)
		tbl.Row(row...)
	}
	return tbl.Render()
}

// wrap breaks text into lines of width cells at most, and cuts it to n
// lines. The last line of a cut text ends with an ellipsis.
func wrap(text string, width, n int) string {
	lines := strings.Split(ansi.Wrap(text, width, ""), "\n")
	if len(lines) > n {
		last, _, _ := strings.Cut(ansi.Wrap(strings.Join(lines[n-1:], " "), width-1, ""), "\n")
		lines = append(lines[:n-1], strings.TrimRight(last, " ")+"…")
	}
	return strings.Join(lines, "\n")
}

func columnWidth(rows [][]string, col int) int {
	w := 0
	for _, r := range rows {
		w = max(w, ansi.StringWidth(r[col]))
	}
	return w
}

// text describes the row: the title of one finding, or the count of the
// vulnerabilities by severity, as "6 vulnerabilities: 2 critical, 4 high".
// When that is wider than room, the count leaves out the total. A
// vulnerability row ends with the version that fixes each of its findings.
func (r row) text(room int) string {
	var fix string
	if v := r.fix(); v != "" {
		fix = fmt.Sprintf(" (fix %s)", render.Text(v))
	}
	if len(r) == 1 {
		return render.Title(r[0]) + fix
	}
	counts := map[finding.Severity]int{}
	for _, f := range r {
		counts[f.Severity]++
	}
	var by []string
	for _, sev := range finding.Severities() {
		if n := counts[sev]; n > 0 {
			by = append(by, fmt.Sprintf("%d %s", n, sev))
		}
	}
	short := strings.Join(by, ", ") + fix
	if full := plural(len(r), "vulnerability", "vulnerabilities") + ": " + short; ansi.StringWidth(full) <= room {
		return full
	}
	return short
}

// fix is the highest fixed version of a vulnerability row. It is empty when
// a finding of the row has no fixed version.
func (r row) fix() string {
	var fix string
	for _, f := range r {
		if f.Family != finding.FamilyVulnerability || f.Remediation == nil || f.Remediation.FixedVersion == "" {
			return ""
		}
		if v := f.Remediation.FixedVersion; fix == "" || semver.IsAhead(fix, v) {
			fix = v
		}
	}
	return fix
}

// findingHints says what the table leaves out, and where to read it.
func findingHints(findings int, rows []row, shown, suppressed int) []string {
	const all = "vet report show --all lists each finding."
	var hints []string
	grouped := len(rows) < findings
	switch more := len(rows) - shown; {
	case grouped && more > 0:
		hints = append(hints, fmt.Sprintf("%s. The table shows %d of %d rows.", vulnerabilityCount(rows), shown, len(rows)), all)
	case grouped:
		hints = append(hints, vulnerabilityCount(rows)+". "+all)
	case more > 0:
		hints = append(hints, fmt.Sprintf("%s. %s", plural(more, "more finding", "more findings"), all))
	}
	switch {
	case suppressed == 1:
		hints = append(hints, "1 suppressed finding. vet report show -o json lists it.")
	case suppressed > 1:
		hints = append(hints, fmt.Sprintf("%d suppressed findings. vet report show -o json lists them.", suppressed))
	}
	for i, h := range hints {
		hints[i] = section.Hint(h)
	}
	return hints
}

// vulnerabilityCount counts the vulnerability findings and their packages,
// as "85 vulnerabilities in 3 packages".
func vulnerabilityCount(rows []row) string {
	findings, packages := 0, 0
	for _, r := range rows {
		if r[0].Family == finding.FamilyVulnerability {
			findings += len(r)
			packages++
		}
	}
	return fmt.Sprintf("%s in %s", plural(findings, "vulnerability", "vulnerabilities"), plural(packages, "package", "packages"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
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
	wide := output.Width() >= wideWidth
	headers := []string{"KIND"}
	if delta {
		headers = append(headers, "CHANGE")
	}
	headers = append(headers, "CAPABILITY", "TAGS", "WHERE")
	if wide {
		headers = append(headers, "CALL")
	}
	tbl := table.New().Headers(headers...)
	shown := caps
	if s.limit > 0 && len(shown) > s.limit {
		shown = shown[:s.limit]
	}
	for _, c := range shown {
		row := []string{strings.ToUpper(string(c.Kind()))}
		if delta {
			row = append(row, strings.ToLower(string(c.Change)))
		}
		row = append(row, render.Truncate(render.Text(c.Name()), 40), tags(c), CapabilityWhere(c))
		if wide {
			row = append(row, call(c))
		}
		tbl.Row(row...)
	}
	parts := []string{style.Heading("AI and crypto: " + kindCounts(caps)), tbl.Render()}
	if more := len(caps) - len(shown); more > 0 {
		parts = append(parts, section.Hint(plural(more, "more capability", "more capabilities")+". vet report capability list lists each one."))
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

// call is the function that the first call site calls.
func call(c *report.Capability) string {
	if len(c.Occurrences) == 0 {
		return ""
	}
	return render.Text(c.Occurrences[0].Callee)
}

// kindCounts counts the capabilities of each kind, as "2 AI, 1 crypto".
func kindCounts(caps []*report.Capability) string {
	counts := map[report.CapabilityKind]int{}
	for _, c := range caps {
		counts[c.Kind()]++
	}
	var out []string
	for _, k := range []struct {
		kind  report.CapabilityKind
		label string
	}{{report.CapabilityAI, "AI"}, {report.CapabilityCrypto, "crypto"}, {report.CapabilityOther, "other"}} {
		if n := counts[k.kind]; n > 0 {
			out = append(out, fmt.Sprintf("%d %s", n, k.label))
		}
	}
	return strings.Join(out, ", ")
}

// tags lists the tags other than the kind tag, and then the weak tag as a
// badge in the colour of a high severity.
func tags(c *report.Capability) string {
	var out []string
	weak := false
	for _, t := range c.DetailTags() {
		if t == report.TagWeak {
			weak = true
			continue
		}
		out = append(out, render.Text(t))
	}
	text := strings.Join(out, ", ")
	if !weak {
		return text
	}
	b := style.Badge(theme.RoleHigh, strings.ToUpper(report.TagWeak))
	switch {
	case text == "":
		return b
	case strings.HasPrefix(ansi.Strip(b), " "):
		// A colour badge starts with a padding cell, which is the space
		// after the comma.
		return text + "," + b
	}
	return text + ", " + b
}

func cards(t *report.Trailer) []stat.Card {
	sum := t.Summary
	crit, high := theme.RoleCritical, theme.RoleHigh
	cs := []stat.Card{
		{Label: "Packages", Value: strconv.Itoa(sum.Packages)},
		{Label: "Findings", Value: strconv.Itoa(sum.Findings)},
		{Label: "Critical", Value: strconv.Itoa(sum.BySeverity[finding.SeverityCritical]), Accent: &crit},
		{Label: "High", Value: strconv.Itoa(sum.BySeverity[finding.SeverityHigh]), Accent: &high},
	}
	switch t.Gate.Outcome {
	case report.GatePass:
		pass := theme.RoleSuccess
		cs = append(cs, stat.Card{Label: "Gate", Value: "PASS", Accent: &pass})
	case report.GateFail:
		fail := theme.RoleError
		cs = append(cs, stat.Card{Label: "Gate", Value: "FAIL", Accent: &fail})
	}
	return cs
}

// severityRoles maps each severity to the colour role of its badge.
var severityRoles = map[finding.Severity]theme.Role{
	finding.SeverityCritical: theme.RoleCritical,
	finding.SeverityHigh:     theme.RoleHigh,
	finding.SeverityMedium:   theme.RoleMedium,
	finding.SeverityLow:      theme.RoleLow,
	finding.SeverityInfo:     theme.RoleInfo,
}

func badge(s finding.Severity) string {
	role, ok := severityRoles[s]
	if !ok {
		role = theme.RoleInfo
	}
	return style.Badge(role, strings.ToUpper(string(s)))
}

// OptionsSchema returns the JSON Schema of the options.
func (s Sink) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var _ plugin.Schemer = Sink{}

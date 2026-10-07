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

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/internal/tui/stat"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/internal/tui/table"
	"github.com/safedep/vet/v2/internal/tui/theme"
	"github.com/safedep/vet/v2/model"
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

// textWidth is the FINDING width under which the table drops CONTROL, then
// WHERE.
const textWidth = 24

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
	if sum := t.Summary; sum.Manifests == 0 && sum.Packages == 0 && sum.Findings == 0 && sum.Capabilities == 0 && sum.Inventory == 0 {
		// A scan that read nothing has nothing to count. The scan view
		// warns that it found no manifest, so zero cards and "No
		// findings" do not read as a clean result.
		return nil
	}

	var open []*finding.Finding
	var ids []string
	var tools []*report.InventoryItem
	changed := 0
	err := render.EachRecord(ctx, r, func(rec *report.Record) error {
		switch f := rec.Finding; {
		case rec.Package != nil && rec.Package.Change.Introduces():
			changed++
		case rec.Inventory != nil:
			tools = append(tools, rec.Inventory)
		case f != nil:
			ids = append(ids, f.ID)
			if !f.Suppressed() {
				open = append(open, f)
			}
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

	packages := t.Summary.Packages
	if delta {
		packages = changed
	}
	parts := []string{stat.Render(cards(h, t, packages)...)}
	change, same := sameChange(shown)
	if len(shown) == 0 {
		checked := plural(packages, "package", "packages")
		if delta {
			checked = plural(packages, "changed package", "changed packages")
		}
		parts = append(parts, style.Success("No findings. "+checked+" checked."))
	} else {
		parts = append(parts, findingTable(shown, report.ShortIDLength(ids), delta && !same, output.Width()))
	}
	hints := findingHints(len(open), rows, len(shown), t.Summary.Suppressed)
	if text := changeHint(change); delta && same && text != "" {
		hints = append([]string{section.Hint(text)}, hints...)
	}
	if len(hints) > 0 {
		parts = append(parts, strings.Join(hints, "\n"))
	}
	if len(tools) > 0 {
		parts = append(parts, s.toolTable(tools)...)
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
	// A finding that fails the gate comes first, so the row limit never
	// hides it.
	slices.SortStableFunc(rows, func(a, b row) int {
		if fa, fb := a.failing(), b.failing(); fa != fb {
			if fa {
				return -1
			}
			return 1
		}
		return b[0].Severity.Rank() - a[0].Severity.Rank()
	})
	return rows
}

// findingTable drops CONTROL and WHERE on a narrow terminal. FINDING takes
// the width that the other columns leave, and wraps onto a second line, so
// that a cut falls on the FINDING text and not on the subject or the place.
// When FINDING gets less than textWidth, the table drops CONTROL, then
// WHERE.
func findingTable(rows []row, idLen int, delta bool, width int) string {
	wide := width >= wideWidth
	l := findingLayout(rows, idLen, delta, wide, wide)
	if l.room(width) < textWidth && wide {
		l = findingLayout(rows, idLen, delta, false, true)
	}
	if l.room(width) < textWidth && wide {
		l = findingLayout(rows, idLen, delta, false, false)
	}
	room := max(l.room(width), minTextWidth)
	tbl := table.New().Headers(l.cells[0]...)
	for i, row := range l.cells[1:] {
		row[l.textAt] = wrap(rows[i].text(room), room, textLines)
		tbl.Row(row...)
	}
	return tbl.Render()
}

// layout is the cells of the findings table with an empty FINDING column.
type layout struct {
	cells  [][]string
	textAt int
}

func findingLayout(rows []row, idLen int, delta, control, where bool) layout {
	headers := []string{"SEVERITY", "ID"}
	gated := slices.ContainsFunc(rows, func(r row) bool { return r.gate() != nil })
	if gated {
		headers = append(headers, "GATE")
	}
	if control {
		headers = append(headers, "CONTROL")
	}
	if delta {
		headers = append(headers, "CHANGE")
	}
	headers = append(headers, "SUBJECT", "FINDING")
	textAt := len(headers) - 1
	if where {
		headers = append(headers, "WHERE")
	}
	cells := [][]string{headers}
	for _, r := range rows {
		f := r[0]
		row := []string{badge(f.Severity), f.ID[:min(idLen, len(f.ID))]}
		if gated {
			row = append(row, gateText(r.gate()))
		}
		if control {
			row = append(row, render.Text(f.ControlID))
		}
		if delta {
			row = append(row, strings.ToLower(string(f.Change)))
		}
		row = append(row, render.Subject(f), "")
		if where {
			row = append(row, render.Where(f))
		}
		cells = append(cells, row)
	}
	return layout{cells: cells, textAt: textAt}
}

// room is the width that the other columns leave to FINDING. Each column
// takes two cells of padding and one of border, and the table one more
// border.
func (l layout) room(width int) int {
	room := width - 1 - 3
	for i := range l.cells[0] {
		if i != l.textAt {
			room -= columnWidth(l.cells, i) + 3
		}
	}
	return room
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

// gate is the gate record of the row: the first finding that fails the
// gate, else the first finding with a record.
func (r row) gate() *finding.GateRecord {
	var first *finding.GateRecord
	for _, f := range r {
		if f.Fails() {
			return f.Gate
		}
		if first == nil {
			first = f.Gate
		}
	}
	return first
}

func (r row) failing() bool { return r.gate() != nil && r.gate().Action == finding.GateActionFail }

// gateText is the short form of a gate record, as "fail no-malware" or
// "warn --fail-on high".
func gateText(g *finding.GateRecord) string {
	if g == nil {
		return ""
	}
	parts := slices.Clone(g.Rules)
	if g.FailOn != "" {
		parts = append(parts, "--fail-on "+g.FailOn)
	}
	return render.Text(string(g.Action) + " " + strings.Join(parts, ", "))
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

// fix is the highest fixed version of a vulnerability row, under the order
// of the ecosystem. With no order it lists each fixed version. It is empty
// when a finding of the row has no fixed version.
func (r row) fix() string {
	var versions []model.PackageVersion
	for _, f := range r {
		if f.Family != finding.FamilyVulnerability || f.Remediation == nil || f.Remediation.FixedVersion == "" || f.Subject.Package == nil {
			return ""
		}
		id, err := f.Subject.Package.PackageVersion()
		if err != nil {
			return ""
		}
		v := id.WithVersion(f.Remediation.FixedVersion)
		if !slices.ContainsFunc(versions, v.Equal) {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return ""
	}
	highest := versions[0]
	for _, v := range versions[1:] {
		c, err := v.Compare(highest)
		if err != nil {
			raw := make([]string, len(versions))
			for i, v := range versions {
				raw[i] = v.RawVersion()
			}
			return strings.Join(raw, ", ")
		}
		if c > 0 {
			highest = v
		}
	}
	return highest.RawVersion()
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

// sameChange returns the change of the rows when each row has the same
// change. A pull request table then needs no CHANGE column.
func sameChange(rows []row) (model.Change, bool) {
	if len(rows) == 0 {
		return "", false
	}
	c := rows[0][0].Change
	for _, r := range rows[1:] {
		if r[0].Change != c {
			return "", false
		}
	}
	return c, true
}

// changeVerbs name what a pull request does to a package or a file.
var changeVerbs = map[model.Change]string{
	model.ChangeAdded:      "adds",
	model.ChangeUpgraded:   "upgrades",
	model.ChangeDowngraded: "downgrades",
	model.ChangeModified:   "changes",
}

// changeHint says the change of each row of a pull request table with no
// CHANGE column.
func changeHint(c model.Change) string {
	if v, ok := changeVerbs[c]; ok {
		return "Each finding is on a package or a file that the change " + v + "."
	}
	return ""
}

// cards counts the packages and the findings. A pull request scan counts
// the packages that it changes. An endpoint audit also counts the tools.
func cards(h *report.Header, t *report.Trailer, packages int) []stat.Card {
	sum := t.Summary
	crit, high := theme.RoleCritical, theme.RoleHigh
	var cs []stat.Card
	if h.Scan.Kind == report.ScanKindEndpoint {
		cs = append(cs, stat.Card{Label: "Tools", Value: strconv.Itoa(sum.Inventory)})
	}
	label := "Packages"
	if h.Scan.Mode == report.ScanModeDelta {
		label = "Changed"
	}
	cs = append(cs, []stat.Card{
		{Label: label, Value: strconv.Itoa(packages)},
		{Label: "Findings", Value: strconv.Itoa(sum.Findings)},
		{Label: "Critical", Value: strconv.Itoa(sum.BySeverity[finding.SeverityCritical]), Accent: &crit},
		{Label: "High", Value: strconv.Itoa(sum.BySeverity[finding.SeverityHigh]), Accent: &high},
	}...)
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

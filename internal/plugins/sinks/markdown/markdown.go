// Package markdown is the markdown format, for a job summary or a pull
// request comment: the gate, what to do, a table of the findings that block,
// a table of the findings to review and a closed list of the other findings
// for each control.
package markdown

import (
	"cmp"
	"context"
	"fmt"
	"html"
	"io"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "markdown"

// Sink writes the markdown format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

const (
	// maxTitle is the length of a title in a table, so that a long
	// advisory summary does not make the table too wide.
	maxTitle = 80
	// maxSteps bounds the steps of "What to do", and maxPlaces the places
	// that one step lists.
	maxSteps  = 10
	maxPlaces = 5
	// maxRows bounds the rows of a table and the packages of an upgrade
	// step. A job summary holds at most 1 MiB, and the report file has
	// each finding.
	maxRows = render.MaxMembers
)

var icons = map[finding.Severity]string{
	finding.SeverityCritical: "🔴",
	finding.SeverityHigh:     "🟠",
	finding.SeverityMedium:   "🟡",
	finding.SeverityLow:      "⚪",
	finding.SeverityInfo:     "🔵",
}

// page is the input of one markdown report.
type page struct {
	header  *report.Header
	trailer *report.Trailer
	view    overview.Overview
	// idLength is the length of the short finding ids, which vet report
	// finding show takes.
	idLength int
}

// Write writes the report.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	view, err := overview.Read(ctx, r)
	if err != nil {
		return err
	}
	ids := make([]string, len(view.Findings))
	for i, f := range view.Findings {
		ids[i] = f.ID
	}
	p := page{header: r.Header(), trailer: r.Trailer(), view: view, idLength: report.ShortIDLength(ids)}
	sec := view.Sections(p.trailer.Gate)
	review := sec.ToReview()
	var b strings.Builder
	p.heading(&b)
	p.status(&b, sec)
	if len(sec.Blocking) > 0 {
		p.todo(&b, sec.Blocking)
	} else {
		p.todo(&b, review)
	}
	p.table(&b, "Blocking findings", sec.Blocking, true)
	p.table(&b, "Findings to review", review, false)
	p.others(&b, sec.Rest, len(sec.Blocking) > 0)
	p.suppressed(&b)
	p.footer(&b)
	_, err = io.WriteString(w, b.String())
	return err
}

func (p page) delta() bool { return p.header.Scan.Mode == report.ScanModeDelta }

func (p page) reach() bool {
	return p.header.Scan.Reach != nil && p.header.Scan.Reach.Status == report.ReachComputed
}

func (p page) heading(b *strings.Builder) {
	fmt.Fprintf(b, "## vet %s", p.header.Scan.Kind)
	switch p.trailer.Gate.Outcome {
	case report.GateFail:
		b.WriteString(" · ❌ The gate failed")
	case report.GatePass:
		b.WriteString(" · ✅ The gate passed")
	}
	b.WriteString("\n\n")
}

// status says what blocks, what vet checked and what it found.
func (p page) status(b *strings.Builder, sec overview.Sections) {
	where := "this scan"
	if p.delta() {
		where = "this pull request"
	}
	var parts []string
	switch n := len(sec.Blocking); {
	case n > 0:
		by, count := blockedBy(sec.Blocking)
		line := fmt.Sprintf("**%s %s** %s.", humanize.Count(n, "finding"), verb(n, "blocks", "block"), where)
		if by != "" {
			line = fmt.Sprintf("%s %s **%s** in %s.", capitalize(by), verb(count, "blocks", "block"), humanize.Count(n, "finding"), where)
		}
		parts = append(parts, line)
	case p.trailer.Gate.Outcome == report.GateFail:
		parts = append(parts, "The gate failed. No open finding blocks it.")
	case p.trailer.Gate.Outcome == report.GatePass:
		parts = append(parts, "No finding blocks "+where+".")
	default:
		parts = append(parts, "The scan has no gate.")
	}
	sum := p.trailer.Summary
	found := "no findings"
	if sum.Findings > 0 {
		found = humanize.Count(sum.Findings, "finding")
	}
	parts = append(parts, fmt.Sprintf("vet checked %s and found %s.", humanize.Count(sum.Packages, "package"), found))
	if n := sum.Suppressed; n > 0 {
		parts = append(parts, fmt.Sprintf("The policy suppresses %s.", humanize.Count(n, "more finding")))
	}
	b.WriteString(strings.Join(parts, " ") + "\n\n")
}

// blockedBy names the rules and the --fail-on value that block the
// findings, as "policy rule no-malware and --fail-on attacks", in markdown.
// It also counts them.
func blockedBy(fs []*finding.Finding) (string, int) {
	var all finding.GateRecord
	for _, f := range fs {
		g := f.Gate
		if g == nil {
			continue
		}
		all.Rules = appendNew(all.Rules, g.Rules...)
		all.Broken = appendNew(all.Broken, g.Broken...)
		all.FailOn = cmp.Or(all.FailOn, g.FailOn)
	}
	by := all.Cause()
	if len(all.Broken) > 0 && all.FailOn == "" {
		// The clause "which did not evaluate" ends the subject.
		by += ","
	}
	n := len(all.Rules) + len(all.Broken)
	if all.FailOn != "" {
		n++
	}
	return render.Markdown(render.Text(by)), n
}

func appendNew(list []string, items ...string) []string {
	for _, s := range items {
		if !slices.Contains(list, s) {
			list = append(list, s)
		}
	}
	return list
}

// todo lists the steps that clear the findings: the attacks first, then the
// upgrades of each manifest, then each other item, then the help of each
// policy rule.
func (p page) todo(b *strings.Builder, fs []*finding.Finding) {
	ups, rest := p.upgrades(fs)
	attacks, items := itemsOf(render.Groups(rest))
	var steps []string
	for _, it := range attacks {
		steps = append(steps, p.itemStep(it))
	}
	for _, u := range ups {
		steps = append(steps, upgradeStep(u))
	}
	for _, it := range items {
		steps = append(steps, p.itemStep(it))
	}
	help := policyHelp(fs)
	if len(steps) == 0 && len(help) == 0 {
		return
	}
	b.WriteString("### What to do\n\n")
	for i, s := range steps[:min(len(steps), maxSteps)] {
		fmt.Fprintf(b, "%d. %s\n", i+1, s)
	}
	if n := len(steps) - maxSteps; n > 0 {
		fmt.Fprintf(b, "\nThis list leaves out %s. The tables show their findings.\n", humanize.Count(n, "more step"))
	}
	if len(help) > 0 {
		if len(steps) > 0 {
			b.WriteString("\n")
		}
		b.WriteString("**Policy help**\n\n" + strings.Join(help, "\n") + "\n")
	}
	b.WriteString("\n")
}

// policyHelp is one line for each policy rule with help or a link. A gate
// record takes them from its first rule.
func policyHelp(fs []*finding.Finding) []string {
	var lines []string
	seen := map[string]bool{}
	for _, f := range fs {
		g := f.Gate
		if g == nil || len(g.Rules) == 0 || seen[g.Rules[0]] || g.Help == "" && render.SafeURL(g.Link) == "" {
			continue
		}
		seen[g.Rules[0]] = true
		var parts []string
		if g.Help != "" {
			parts = append(parts, render.Bounded(render.Text(g.Help), render.MaxText))
		}
		if u := render.SafeURL(g.Link); u != "" {
			parts = append(parts, fmt.Sprintf("[Policy guidance](%s)", u))
		}
		lines = append(lines, fmt.Sprintf("- %s: %s", render.ShortCode(render.Text(g.Rules[0])), strings.Join(parts, " · ")))
	}
	return lines
}

// manifestUpgrades are the upgrades of the packages of one manifest.
type manifestUpgrades struct {
	manifest string
	upgrades []overview.Upgrade
}

// upgrades puts the findings that an upgrade fixes together for each
// manifest. It returns the other findings in their order. An attack has a
// step of its own, because an upgrade does not undo what it ran.
func (p page) upgrades(fs []*finding.Finding) ([]manifestUpgrades, []*finding.Finding) {
	pkgs := slices.DeleteFunc(slices.Clone(fs), func(f *finding.Finding) bool { return f.Subject.Package == nil || f.Attack != nil })
	fixed := map[*finding.Finding]bool{}
	var out []manifestUpgrades
	for _, group := range groupBy(pkgs, func(f *finding.Finding) string { return f.Subject.Package.ManifestPath }) {
		ups := overview.Upgrades(group, p.view.Latest)
		if len(ups) == 0 {
			continue
		}
		slices.SortStableFunc(ups, func(a, b overview.Upgrade) int { return cmp.Compare(len(b.Findings), len(a.Findings)) })
		for _, u := range ups {
			for _, f := range u.Findings {
				fixed[f] = true
			}
		}
		out = append(out, manifestUpgrades{manifest: group[0].Subject.Package.ManifestPath, upgrades: ups})
	}
	rest := slices.DeleteFunc(slices.Clone(fs), func(f *finding.Finding) bool { return fixed[f] })
	return out, rest
}

// upgradeStep names each upgrade of one manifest. It says "can clear" when
// a finding has no fixed version, because the data does not show that the
// version fixes it.
func upgradeStep(m manifestUpgrades) string {
	n, unfixed := 0, 0
	for _, u := range m.upgrades {
		n += len(u.Findings)
		unfixed += u.Unfixed
	}
	head := "**Upgrade " + humanize.Count(len(m.upgrades), "package") + ".**"
	if m.manifest != "" {
		head = fmt.Sprintf("**In %s, upgrade %s.**", render.ShortCode(render.Text(m.manifest)), humanize.Count(len(m.upgrades), "package"))
	}
	claim := "This clears"
	if unfixed > 0 {
		claim = "This can clear"
	}
	lines := []string{fmt.Sprintf("%s %s %s.", head, claim, humanize.Count(n, "finding"))}
	for i, u := range m.upgrades {
		if i == maxRows {
			lines = append(lines, fmt.Sprintf("   - %d more in the full report", len(m.upgrades)-maxRows))
			break
		}
		lines = append(lines, "   - "+upgradeLine(u))
	}
	return strings.Join(lines, "\n")
}

// upgradeLine is one upgrade: the name, each version in use, the version
// to take and the count of its findings.
func upgradeLine(u overview.Upgrade) string {
	from := make([]string, len(u.From))
	for i, v := range u.From {
		from[i] = version(v)
	}
	to := "**" + version(u.To) + "**"
	if u.Latest {
		to += ", the latest version"
	}
	count := humanize.Count(len(u.Findings), "finding")
	if u.Unfixed > 0 && !u.Latest {
		count += fmt.Sprintf(", %d with no known fixed version", u.Unfixed)
	}
	return fmt.Sprintf("%s %s → %s (%s)", render.ShortCode(render.Text(u.Name)), strings.Join(from, ", "), to, count)
}

func version(v model.PackageVersion) string {
	return render.Bounded(render.Text(v.RawVersion()), render.MaxField)
}

// item is the finding groups of one control and one fix, which one step
// of "What to do" names.
type item struct {
	groups []render.Group
	count  int
}

// itemsOf puts the groups of one control and one fix together, in the
// order of their first group. It returns the attacks apart.
func itemsOf(gs []render.Group) (attacks, others []item) {
	for _, groups := range groupBy(gs, func(g render.Group) string { return g.Lead().ControlID + "\x00" + g.Fix() }) {
		it := item{groups: groups}
		for _, g := range groups {
			it.count += len(g.Findings)
		}
		if groups[0].Lead().Attack != nil {
			attacks = append(attacks, it)
			continue
		}
		others = append(others, it)
	}
	return attacks, others
}

// itemStep names the control and the fix of an item, with a line for
// each place.
func (p page) itemStep(it item) string {
	g := it.groups[0]
	line := fmt.Sprintf("**%s (%s).**", render.Bounded(render.Text(p.header.ControlTitle(g.Lead().ControlID)), render.MaxField),
		humanize.Count(it.count, "finding"))
	if fix := g.Fix(); fix != "" {
		line += " " + render.Bounded(fix, render.MaxText)
	}
	var places []string
	for _, g := range it.groups {
		places = appendNew(places, place(g))
	}
	lines := []string{line}
	for i, pl := range places {
		if i == maxPlaces {
			lines = append(lines, fmt.Sprintf("   - %d more", len(places)-maxPlaces))
			break
		}
		lines = append(lines, "   - "+pl)
	}
	return strings.Join(lines, "\n")
}

// place is the subject and the file of a group, on one line.
func place(g render.Group) string {
	f := g.Lead()
	if onlyWhere(f) {
		return render.ShortCode(render.Where(f)) + g.More()
	}
	return render.ShortCode(render.Subject(f)) + g.More() + " in " + render.ShortCode(render.Where(f))
}

// onlyWhere reports that the place of a finding names its subject, as for
// a file with no element.
func onlyWhere(f *finding.Finding) bool {
	s, w := render.Subject(f), render.Where(f)
	path, _ := render.Place(f)
	return s == "" || s == w || s == render.Text(path)
}

// rows puts the findings of one cause in one row. A finding with an
// advisory has a row of its own, so that each advisory shows.
func rows(fs []*finding.Finding) []render.Group {
	var out []render.Group
	for _, g := range render.Groups(fs) {
		if g.Lead().Advisory == "" {
			out = append(out, g)
			continue
		}
		for _, f := range g.Findings {
			out = append(out, render.Group{Findings: []*finding.Finding{f}})
		}
	}
	return out
}

// table writes one row for each finding group. A table of blocking
// findings names only the rules and the --fail-on value in a narrow
// "Blocked by" column.
func (p page) table(b *strings.Builder, title string, fs []*finding.Finding, blocking bool) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s (%d)\n\n", title, len(fs))
	cols := []string{"", "Finding", "Where"}
	if p.delta() {
		cols = append(cols, "Change")
	}
	if p.reach() {
		cols = append(cols, "Reach")
	}
	gated := p.trailer.Gate.Outcome != report.GateNone
	switch {
	case blocking:
		cols = append(cols, "Blocked by")
	case gated:
		cols = append(cols, "Gate")
	}
	writeHeader(b, cols)
	gs := rows(fs)
	for _, g := range gs[:min(len(gs), maxRows)] {
		f := g.Lead()
		cells := []string{kind(g.Severity(), g.Kind()), p.findingCell(f), whereCell(f, g.More())}
		if p.delta() {
			cells = append(cells, changes(g.Findings))
		}
		if p.reach() {
			cells = append(cells, cell(g.Reach().Label()))
		}
		switch {
		case blocking && f.Gate != nil:
			cells = append(cells, render.Markdown(render.Text(f.Gate.Short())))
		case blocking, gated:
			cells = append(cells, gateCell(f.Gate))
		}
		writeRow(b, cells)
	}
	b.WriteString("\n")
	writeMore(b, len(gs))
}

// others lists the findings that the tables do not show, closed, with one
// list for each control.
func (p page) others(b *strings.Builder, fs []*finding.Finding, blocking bool) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "### Other findings (%d)\n\n", len(fs))
	if blocking {
		b.WriteString("They do not block the gate.\n\n")
	}
	for _, group := range groupBy(fs, func(f *finding.Finding) string { return f.ControlID }) {
		p.control(b, group)
	}
}

// control writes the closed list of the findings of one control.
func (p page) control(b *strings.Builder, fs []*finding.Finding) {
	id := fs[0].ControlID
	var tally []string
	for _, group := range groupBy(fs, render.Kind) {
		tally = append(tally, fmt.Sprintf("%d %s", len(group), render.Kind(group[0])))
	}
	fmt.Fprintf(b, "<details><summary><b>%s</b> · %s · %s</summary>\n\n", summaryText(id),
		humanize.Count(len(fs), "finding"), summaryText(strings.Join(tally, ", ")))
	if u := render.SafeURL(render.ControlURL(p.header.Tool.Version, id)); u != "" {
		fmt.Fprintf(b, "[What this control checks](%s)\n\n", u)
	}
	gated := slices.ContainsFunc(fs, func(f *finding.Finding) bool { return f.Gate != nil })
	cols := []string{"", "Finding", "Where"}
	if p.delta() {
		cols = append(cols, "Change")
	}
	if p.reach() {
		cols = append(cols, "Reach")
	}
	if gated {
		cols = append(cols, "Gate")
	}
	writeHeader(b, append(cols, "ID"))
	for _, f := range fs[:min(len(fs), maxRows)] {
		cells := []string{kind(f.Severity, render.Kind(f)), render.Bounded(render.Title(f), maxTitle), whereCell(f, "")}
		if p.delta() {
			cells = append(cells, changes([]*finding.Finding{f}))
		}
		if p.reach() {
			cells = append(cells, cell(f.Reach.Label()))
		}
		if gated {
			cells = append(cells, gateCell(f.Gate))
		}
		writeRow(b, append(cells, p.id(f)))
	}
	b.WriteString("\n")
	writeMore(b, len(fs))
	b.WriteString("</details>\n\n")
}

// writeMore counts the rows that a table leaves out.
func writeMore(b *strings.Builder, n int) {
	if n > maxRows {
		fmt.Fprintf(b, "The full report has %d more.\n\n", n-maxRows)
	}
}

func (p page) suppressed(b *strings.Builder) {
	fs := p.view.Suppressed
	if len(fs) == 0 {
		return
	}
	lines := make([]string, 0, min(len(fs), maxRows)+1)
	for i, f := range fs {
		if i == maxRows {
			lines = append(lines, fmt.Sprintf("- %d more in the full report", len(fs)-maxRows))
			break
		}
		lines = append(lines, fmt.Sprintf("- %s %s: %s", render.ShortCode(render.Text(f.ControlID)), render.ShortCode(render.Subject(f)),
			render.Bounded(render.Text(f.Suppression.Reason), render.MaxField)))
	}
	fmt.Fprintf(b, "<details><summary>%d suppressed</summary>\n\n%s\n\n</details>\n\n", len(fs), strings.Join(lines, "\n"))
}

func (p page) footer(b *strings.Builder) {
	line := "Full report: " + render.Code(overview.FullList(render.Text(p.header.Scan.ID)))
	if len(p.view.Findings) > 0 {
		line += " · One finding: `vet report finding show <id>`"
	}
	b.WriteString("---\n\n" + line + "\n")
}

// findingCell links the advisory of a finding, or the docs of its control,
// with the short id of the finding, above its title.
func (p page) findingCell(f *finding.Finding) string {
	title := render.Title(f)
	var ref string
	if f.Advisory == "" {
		ref = render.Markdown(render.Text(f.ControlID))
		if u := render.SafeURL(render.ControlURL(p.header.Tool.Version, f.ControlID)); u != "" {
			ref = fmt.Sprintf("[%s](%s)", ref, u)
		}
	} else {
		advisory := render.Text(f.Advisory)
		title = strings.TrimPrefix(title, advisory+": ")
		ref = render.Bounded(advisory, render.MaxField)
		if len(f.References) > 0 {
			if u := render.SafeURL(f.References[0]); u != "" {
				ref = fmt.Sprintf("[%s](%s)", ref, u)
			}
		}
	}
	return ref + " · " + p.id(f) + "<br>" + render.Bounded(title, maxTitle)
}

func (p page) id(f *finding.Finding) string { return code(report.ShortID(f.ID, p.idLength)) }

// whereCell shows the subject above the file, or the file alone when it
// names the subject.
func whereCell(f *finding.Finding, more string) string {
	w := code(render.Where(f))
	if onlyWhere(f) {
		return w + more
	}
	return code(render.Subject(f)) + more + "<br>" + w
}

// changes names each change of the findings of a row, so that a row of an
// added and an unchanged package says both.
func changes(fs []*finding.Finding) string {
	var out []string
	for _, f := range fs {
		out = appendNew(out, strings.ToLower(string(f.Change)))
	}
	return cell(strings.Join(out, ", "))
}

func kind(s finding.Severity, label string) string {
	if icon, ok := icons[s]; ok {
		return icon + " " + label
	}
	return label
}

func writeHeader(b *strings.Builder, cols []string) {
	sep := make([]string, len(cols))
	for i := range sep {
		sep[i] = "---"
	}
	writeRow(b, cols)
	writeRow(b, sep)
}

func writeRow(b *strings.Builder, cells []string) {
	b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
}

// gateCell names what blocks or warns on a finding.
func gateCell(g *finding.GateRecord) string {
	if g == nil {
		return ""
	}
	return render.Markdown(render.Text(g.Label() + " " + g.Cause()))
}

// groupBy puts the items with one key together, in the order of their
// first item.
func groupBy[T any](items []T, key func(T) string) [][]T {
	var out [][]T
	at := map[string]int{}
	for _, it := range items {
		k := key(it)
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], it)
	}
	return out
}

func verb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// summaryText escapes text for an HTML summary. A zero-width space after
// each "@" stops a mention.
func summaryText(s string) string {
	return strings.ReplaceAll(html.EscapeString(render.Text(s)), "@", "@\u200b")
}

// cell makes text safe in a table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

// code puts text in a code span of a table cell, bounded to
// render.MaxField runes.
func code(s string) string { return strings.ReplaceAll(render.ShortCode(s), "|", `\|`) }

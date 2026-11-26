// Package markdown is the markdown format, for a job summary or a pull
// request comment: the gate, what to do, a table of the findings that block
// and a closed list of the other findings for each control.
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
	// maxPlaces bounds the places that one step of "What to do" lists.
	maxPlaces = 5
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
	var b strings.Builder
	p.heading(&b)
	p.status(&b, sec)
	if sec.Blocking {
		p.todo(&b, sec.Shown)
	}
	if sec.Blocking {
		p.table(&b, "Blocking findings", sec.Shown, true)
	} else {
		p.table(&b, "Findings to review", sec.Shown, false)
	}
	p.table(&b, "Attacks to review", sec.Attacks, false)
	p.others(&b, sec)
	p.suppressed(&b)
	p.footer(&b)
	_, err = io.WriteString(w, b.String())
	return err
}

func (p page) delta() bool { return p.header.Scan.Mode == report.ScanModeDelta }

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
	switch {
	case sec.Blocking:
		n := len(sec.Shown)
		by, count := blockedBy(sec.Shown)
		line := fmt.Sprintf("**%s %s** %s.", humanize.Count(n, "finding"), verb(n, "blocks", "block"), where)
		if by != "" {
			line = fmt.Sprintf("%s %s **%s** in %s.", capitalize(render.Markdown(by)), verb(count, "blocks", "block"), humanize.Count(n, "finding"), where)
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
		parts = append(parts, fmt.Sprintf("%s %s.", verb(n, "A suppression hides", "Suppressions hide"), humanize.Count(n, "more finding")))
	}
	b.WriteString(strings.Join(parts, " ") + "\n\n")
}

// blockedBy names the rules and the --fail-on value that block the
// findings, as "policy rule no-malware and --fail-on attacks". It also
// counts them.
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
	n := len(all.Rules) + len(all.Broken)
	if all.FailOn != "" {
		n++
	}
	return all.Cause(), n
}

func appendNew(list []string, items ...string) []string {
	for _, s := range items {
		if !slices.Contains(list, s) {
			list = append(list, s)
		}
	}
	return list
}

// todo lists the steps that clear the blocking findings: the attacks
// first, then the upgrades of each manifest, then each other item.
func (p page) todo(b *strings.Builder, fs []*finding.Finding) {
	ups, rest := p.upgrades(fs)
	attacks, items := itemsOf(render.Groups(rest))
	var steps []string
	for _, c := range attacks {
		steps = append(steps, p.itemStep(c))
	}
	for _, u := range ups {
		steps = append(steps, upgradeStep(u))
	}
	for _, c := range items {
		steps = append(steps, p.itemStep(c))
	}
	if len(steps) == 0 {
		return
	}
	b.WriteString("### What to do\n\n")
	for i, s := range steps {
		fmt.Fprintf(b, "%d. %s\n", i+1, s)
	}
	b.WriteString("\n")
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
	var manifests []string
	byManifest := map[string][]*finding.Finding{}
	for _, f := range fs {
		if f.Subject.Package == nil || f.Attack != nil {
			continue
		}
		m := f.Subject.Package.ManifestPath
		if _, ok := byManifest[m]; !ok {
			manifests = append(manifests, m)
		}
		byManifest[m] = append(byManifest[m], f)
	}
	fixed := map[*finding.Finding]bool{}
	var out []manifestUpgrades
	for _, m := range manifests {
		ups := overview.Upgrades(byManifest[m], p.view.Latest)
		if len(ups) == 0 {
			continue
		}
		slices.SortStableFunc(ups, func(a, b overview.Upgrade) int { return cmp.Compare(len(b.Findings), len(a.Findings)) })
		for _, u := range ups {
			for _, f := range u.Findings {
				fixed[f] = true
			}
		}
		out = append(out, manifestUpgrades{manifest: m, upgrades: ups})
	}
	rest := slices.DeleteFunc(slices.Clone(fs), func(f *finding.Finding) bool { return fixed[f] })
	return out, rest
}

// upgradeStep names each upgrade of one manifest. A version that the data
// does not mark as fixed is the latest version, and can still have the
// vulnerability.
func upgradeStep(m manifestUpgrades) string {
	n, latest := 0, false
	for _, u := range m.upgrades {
		n += len(u.Findings)
		latest = latest || u.Latest
	}
	head := "**Upgrade " + humanize.Count(len(m.upgrades), "package") + ".**"
	if m.manifest != "" {
		head = fmt.Sprintf("**In %s, upgrade %s.**", render.ShortCode(render.Text(m.manifest)), humanize.Count(len(m.upgrades), "package"))
	}
	claim := "This clears"
	if latest {
		claim = "This can clear"
	}
	lines := []string{fmt.Sprintf("%s %s %s.", head, claim, humanize.Count(n, "finding"))}
	for _, u := range m.upgrades {
		to := "**" + render.Bounded(render.Text(u.To.RawVersion()), render.MaxField) + "**"
		if u.Latest {
			to += ", the latest version"
		}
		lines = append(lines, fmt.Sprintf("   - %s %s → %s (%s)", render.ShortCode(render.Text(u.Name)),
			render.Bounded(render.Text(u.From.RawVersion()), render.MaxField), to, humanize.Count(len(u.Findings), "finding")))
	}
	return strings.Join(lines, "\n")
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
	var out []item
	at := map[string]int{}
	for _, g := range gs {
		k := g.Lead().ControlID + "\x00" + g.Fix()
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, item{})
		}
		out[i].groups = append(out[i].groups, g)
		out[i].count += len(g.Findings)
	}
	for _, c := range out {
		if c.groups[0].Lead().Attack != nil {
			attacks = append(attacks, c)
			continue
		}
		others = append(others, c)
	}
	return attacks, others
}

// itemStep names the control and the fix of an item, with a line for
// each place.
func (p page) itemStep(c item) string {
	g := c.groups[0]
	line := fmt.Sprintf("**%s (%s).**", render.Bounded(render.Text(p.header.ControlTitle(g.Lead().ControlID)), render.MaxField),
		humanize.Count(c.count, "finding"))
	if fix := g.Fix(); fix != "" {
		line += " " + render.Bounded(fix, render.MaxText)
	}
	lines := []string{line}
	for i, g := range c.groups {
		if i == maxPlaces {
			lines = append(lines, fmt.Sprintf("   - %d more in the table", len(c.groups)-maxPlaces))
			break
		}
		lines = append(lines, "   - "+place(g))
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
	reach := p.header.Scan.Reach != nil && p.header.Scan.Reach.Status == report.ReachComputed
	if reach {
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
	for _, g := range render.Groups(fs) {
		f := g.Lead()
		cells := []string{kind(g.Severity(), g.Kind()), p.findingCell(f), whereCell(f, g.More())}
		if p.delta() {
			cells = append(cells, change(f))
		}
		if reach {
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
}

// others lists the findings that the tables do not show, closed, with one
// list for each control.
func (p page) others(b *strings.Builder, sec overview.Sections) {
	fs := sec.Rest
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "### Other findings (%d)\n\n", len(fs))
	if sec.Blocking {
		b.WriteString("They do not block the gate.\n\n")
	}
	var controls []string
	byControl := map[string][]*finding.Finding{}
	for _, f := range fs {
		if _, ok := byControl[f.ControlID]; !ok {
			controls = append(controls, f.ControlID)
		}
		byControl[f.ControlID] = append(byControl[f.ControlID], f)
	}
	for _, id := range controls {
		p.control(b, id, byControl[id])
	}
}

// control writes the closed list of the findings of one control.
func (p page) control(b *strings.Builder, id string, fs []*finding.Finding) {
	var kinds []string
	count := map[string]int{}
	gated := false
	for _, f := range fs {
		k := render.Kind(f)
		if count[k] == 0 {
			kinds = append(kinds, k)
		}
		count[k]++
		gated = gated || f.Gate != nil
	}
	tally := make([]string, len(kinds))
	for i, k := range kinds {
		tally[i] = fmt.Sprintf("%d %s", count[k], k)
	}
	fmt.Fprintf(b, "<details><summary><b>%s</b> · %s · %s</summary>\n\n", html.EscapeString(render.Text(id)),
		humanize.Count(len(fs), "finding"), html.EscapeString(strings.Join(tally, ", ")))
	if u := render.SafeURL(render.ControlURL(p.header.Tool.Version, id)); u != "" {
		fmt.Fprintf(b, "[What this control checks](%s)\n\n", u)
	}
	cols := []string{"", "Finding", "Where"}
	if p.delta() {
		cols = append(cols, "Change")
	}
	if gated {
		cols = append(cols, "Gate")
	}
	writeHeader(b, append(cols, "ID"))
	for _, f := range fs {
		cells := []string{kind(f.Severity, render.Kind(f)), render.Bounded(render.Title(f), maxTitle), whereCell(f, "")}
		if p.delta() {
			cells = append(cells, change(f))
		}
		if gated {
			cells = append(cells, gateCell(f.Gate))
		}
		writeRow(b, append(cells, p.id(f)))
	}
	b.WriteString("\n</details>\n\n")
}

func (p page) suppressed(b *strings.Builder) {
	fs := p.view.Suppressed
	if len(fs) == 0 {
		return
	}
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = fmt.Sprintf("- `%s` %s: %s", cell(f.ControlID), code(render.Subject(f)), cell(render.Text(f.Suppression.Reason)))
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

// whereCell shows the subject above the file, or the file alone when it
// names the subject.
func whereCell(f *finding.Finding, more string) string {
	w := code(render.Where(f))
	if onlyWhere(f) {
		return w + more
	}
	return code(render.Subject(f)) + more + "<br>" + w
}

func (p page) id(f *finding.Finding) string { return code(report.ShortID(f.ID, p.idLength)) }

func kind(s finding.Severity, label string) string {
	if icon, ok := icons[s]; ok {
		return icon + " " + label
	}
	return label
}

func change(f *finding.Finding) string { return strings.ToLower(string(f.Change)) }

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

// cell makes text safe in a table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

// code puts text in a code span of a table cell, bounded to
// render.MaxField runes.
func code(s string) string { return strings.ReplaceAll(render.ShortCode(s), "|", `\|`) }

package prcomment

import (
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

const (
	// maxBody bounds the comment, and maxVisible the text outside a closed
	// details block. A long comment buries the next step, and the full
	// cards are in the step summary and the report artifact. A dialect with
	// no details block shows each line, so it has the body budget only.
	maxBody    = 12000
	maxVisible = 2500
	// maxComment is the size limit of a GitHub comment. The state block and
	// the agent block are for machines, so they count only against it.
	maxComment = 65536
	// maxURL bounds a file link. A longer link shows the path with no link,
	// so that one long path cannot push the comment out of its budget.
	maxURL = 500
	// maxFull bounds the groups that show as a card.
	maxFull = 5
	// maxEntries bounds the snippet entries of one group.
	maxEntries = 20
	maxField   = render.MaxField
	maxText    = render.MaxText
	// maxAlerts bounds the lines of an alert.
	maxAlerts = 5

	repoURL  = "https://github.com/safedep/vet"
	devRef   = "v2"
	formFile = "false-positive.yml"
)

// level is how much of the comment shows. The body takes the first level
// that fits in the budget.
type level struct {
	// full is the number of groups that show as a card. The other groups
	// show as one line each.
	full int
	// lines bounds each list of lines. A list with no lines shows a count.
	lines int
	// snippet shows the policy snippet, and state the state block and the
	// agent block.
	snippet, state bool
}

var levels = []level{
	{full: maxFull, lines: 100, snippet: true, state: true},
	{full: 3, lines: 100, snippet: true, state: true},
	{full: 1, lines: 100, snippet: true, state: true},
	{full: 1, lines: 30, snippet: true, state: true},
	{full: 0, lines: 30, snippet: true, state: true},
	{full: 0, lines: 10, snippet: true, state: true},
	{full: 0, lines: 10, state: true},
	{full: 0, lines: 10, snippet: true},
	{full: 0, lines: 10},
	{},
}

// hidden matches the details blocks and the HTML comments that the comment
// writes. Each one starts at the start of a line. Text from the scanned
// code never starts a line, so a name such as "<details>" in a code span
// does not hide text from the count.
var hidden = regexp.MustCompile(`(?ms)^<details><summary>.*?^</details>$|^<!--.*?-->$`)

// visible is the text that a reader sees before they open a details block.
func visible(body string) string { return hidden.ReplaceAllString(body, "") }

// dialect is what the markup of a platform renders.
type dialect struct {
	// Alerts renders > [!CAUTION] and its kin.
	Alerts bool
	// HTML renders <details>, <sub> and HTML entities.
	HTML bool
}

var githubDialect = dialect{Alerts: true, HTML: true}

// markerOf finds the comment of vet among the comments of a change. The
// key keeps apart the comments of two vet steps on one change.
func markerOf(key string) string {
	if key == "" {
		return "<!-- vet:pr-comment v1 -->"
	}
	return "<!-- vet:pr-comment v1 " + key + " -->"
}

// links point to the change on its platform. Each field can be empty.
type links struct {
	Server, Repository, Head, Run, RunID string
	// Prefix is the path of the scan target in the repository, with a
	// trailing "/", or "" for the root. File links need it.
	Prefix string
	// NoFiles turns off the file links, when vet cannot place the target
	// in the repository.
	NoFiles bool
}

// input is what the comment shows.
type input struct {
	header  *report.Header
	trailer *report.Trailer
	view    overview.Overview
	links   links
	dialect dialect
	// old is the state of the comment that this run edits, or nil.
	old *state
	// via is a footer line of the adapter that posts the comment.
	via string
	// marker is the first line of the comment.
	marker string
	// artifact is the name of the workflow artifact with the JSON report,
	// or "".
	artifact string
}

// body renders the comment at the first level that fits. When no level
// fits, it renders the verdict, the attacks, the status and the footer.
func (c *input) body() string {
	sec := c.sections()
	for _, l := range levels {
		if b, machine := c.render(l, sec); c.fits(b, machine) {
			return b
		}
	}
	var b strings.Builder
	b.WriteString(c.marker + "\n")
	fmt.Fprintf(&b, "### %s\n\n", c.heading(sec))
	c.caution(&b)
	c.status(&b, sec)
	b.WriteString("The findings do not fit in a comment. The full report has them.\n\n")
	c.footer(&b)
	return b.String()
}

// fits reports whether a body fits in the budget. machine is the size of
// the state block and the agent block of the body.
func (c *input) fits(body string, machine int) bool {
	n := utf8.RuneCountInString(body)
	if n > maxComment || n-machine > maxBody {
		return false
	}
	return !c.dialect.HTML || utf8.RuneCountInString(visible(body)) <= maxVisible
}

func (c *input) delta() bool { return c.header.Scan.Mode == report.ScanModeDelta }

// sections splits the open findings. The comment shows the groups that
// fail the gate, else the groups of critical and high findings to review.
// The rest show in a closed list.
type sections struct {
	shown    []render.Group
	blocking bool
	// count is the number of findings in shown.
	count int
	// attacks are the attack groups that do not fail a gate that fails on
	// other findings, as with a gate of policy rules only. An attack never
	// goes to the closed list.
	attacks []render.Group
	rest    []*finding.Finding
}

func (c *input) sections() sections {
	g := c.trailer.Gate
	var blocking, attacks, review, rest []*finding.Finding
	for _, f := range c.view.Findings {
		switch {
		case g.Outcome == report.GateFail && slices.Contains(g.FindingIDs, f.ID):
			blocking = append(blocking, f)
		case f.Attack != nil:
			attacks = append(attacks, f)
		case f.Severity.AtLeast(finding.SeverityHigh):
			review = append(review, f)
		default:
			rest = append(rest, f)
		}
	}
	if len(blocking) > 0 {
		rest = append(review, rest...)
		slices.SortStableFunc(rest, finding.Compare)
		return sections{shown: render.Groups(blocking), blocking: true, count: len(blocking), attacks: render.Groups(attacks), rest: rest}
	}
	review = append(attacks, review...)
	slices.SortStableFunc(review, finding.Compare)
	return sections{shown: render.Groups(review), count: len(review), rest: rest}
}

// render renders the comment at one level. It returns the body and the
// size of its state block and agent block.
func (c *input) render(l level, sec sections) (string, int) {
	var b strings.Builder
	b.WriteString(c.marker + "\n")
	fmt.Fprintf(&b, "### %s\n\n", c.heading(sec))
	c.caution(&b)
	c.next(&b, sec.shown)
	c.warning(&b)
	c.note(&b)
	c.progress(&b)
	c.status(&b, sec)
	title := "Review"
	if sec.blocking {
		title = "Blocking"
	}
	c.section(&b, title, sec.shown, l)
	c.section(&b, "Attacks to review", sec.attacks, l)
	c.details(&b, sec, l.lines)
	if l.snippet {
		c.snippet(&b, slices.Concat(sec.shown, sec.attacks)[:min(len(sec.shown)+len(sec.attacks), maxFull)])
	}
	machine := 0
	if l.state {
		before := utf8.RuneCountInString(b.String())
		c.agent(&b, sec)
		machine = utf8.RuneCountInString(b.String()) - before
	}
	c.footer(&b)
	if l.state {
		if block, ok := c.stateBlock(); ok {
			b.WriteString(block + "\n")
			machine += utf8.RuneCountInString(block) + 1
		}
	}
	return b.String(), machine
}

// heading counts the groups that block, then the groups to review. A
// group is one cause, so a release with 14 platform packages counts once.
func (c *input) heading(sec sections) string {
	where := "this scan"
	if c.delta() {
		where = "this pull request"
	}
	n := len(sec.shown)
	switch {
	case sec.blocking:
		return fmt.Sprintf("❌ vet: %s %s %s", humanize.Count(n, "cause"), verb(n, "blocks", "block"), where)
	case n > 0:
		return fmt.Sprintf("⚠️ vet: %s to review in %s", humanize.Count(n, "cause"), where)
	case len(sec.rest) > 0:
		return "✅ vet: nothing to review in " + where
	}
	return "✅ vet: no findings in " + where
}

// next is the first thing to do: the fix of the first group, with the file,
// the end of a wait and the command.
func (c *input) next(b *strings.Builder, gs []render.Group) {
	i := slices.IndexFunc(gs, func(g render.Group) bool { return g.Fix() != "" })
	if i < 0 {
		return
	}
	g := gs[i]
	fix := md(g.Fix(), maxText)
	line := "**Next step:** " + code(render.Subject(g.Lead())) + g.More()
	if where := c.where(g.Lead()); where != "" {
		line += " in " + where
	}
	line += ": " + fix
	if r := g.Lead().Remediation; r.Command != "" {
		line += " Run " + code(render.Text(r.Command)) + "."
	}
	b.WriteString(line + "\n\n")
}

// caution names each attack. An attack needs action before the merge.
func (c *input) caution(b *strings.Builder) {
	var lines []string
	for _, f := range c.view.Findings {
		if f.Attack != nil {
			lines = append(lines, fmt.Sprintf("%s: %s", code(render.Subject(f)), md(render.Title(f), maxField)))
		}
	}
	if len(lines) == 0 {
		return
	}
	lines = capLines(lines, maxAlerts)
	lines = append(lines, "Do not merge this change. Treat each machine and each CI run that installed or ran it as exposed.")
	c.alert(b, "CAUTION", lines)
}

// warning names the checks that failed open and the files that vet cannot
// read, so a missing finding does not look like a clean result.
func (c *input) warning(b *strings.Builder) {
	checks, files := gaps(c.view.Diagnostics)
	var lines []string
	if len(checks) > 0 {
		lines = append(lines, "Some checks did not complete, so a finding can be missing. Run the job again before you merge.")
		lines = append(lines, diagLines(checks)...)
	}
	if len(files) > 0 {
		lines = append(lines, "vet cannot read some files, so a finding can be missing. Fix the files before you merge.")
		lines = append(lines, diagLines(files)...)
	}
	if len(lines) > 0 {
		c.alert(b, "WARNING", lines)
	}
}

// gaps returns the diagnostics that can hide a finding of the change: the
// checks that did not complete, and the files that vet cannot read. A file
// that the change keeps as it is has no finding of the change.
func gaps(diags []*report.Diagnostic) (checks, files []*report.Diagnostic) {
	for _, d := range diags {
		switch d.Code {
		case report.CodeEnrichUnavailable, report.CodeEnrichFailed,
			report.CodeControlUnavailable, report.CodeControlFailed, report.CodeInvalidFinding:
			checks = append(checks, d)
		case report.CodeExtractFailed:
			if d.Change != model.ChangeUnchanged {
				files = append(files, d)
			}
		}
	}
	return checks, files
}

func diagLines(diags []*report.Diagnostic) []string {
	lines := make([]string, 0, len(diags))
	for _, d := range diags {
		lines = append(lines, fmt.Sprintf("%s: %s", code(d.Component), md(render.Text(d.Message), maxField)))
	}
	return capLines(lines, maxAlerts)
}

// note says that the gate used the policy of the base, when the change
// edits the policy.
func (c *input) note(b *strings.Builder) {
	g := c.trailer.Gate
	if !g.PolicyChanged {
		return
	}
	line := "This change adds a policy. The base branch has no policy, so the gate applies none."
	switch {
	case g.Policy != "":
		line = fmt.Sprintf("This change edits the policy. The gate uses %s.", code(g.Policy))
	case c.baseInvalid():
		line = "This change edits the policy. The policy of the base branch does not load, so the gate applies none until this change merges."
	}
	c.alert(b, "NOTE", []string{line})
}

// baseInvalid reports that the policy of the base branch does not load.
func (c *input) baseInvalid() bool {
	return slices.ContainsFunc(c.view.Diagnostics, func(d *report.Diagnostic) bool {
		return d.Code == report.CodeBasePolicyInvalid
	})
}

func (c *input) progress(b *strings.Builder) {
	base, ok := c.baseline()
	if !ok {
		return
	}
	p := compare(base, ids(c.view.Findings), ids(c.view.Suppressed))
	var parts []string
	for _, part := range []struct {
		n    int
		word string
	}{{len(p.Resolved), "resolved"}, {len(p.New), "new"}, {len(p.Suppressed), "suppressed"}} {
		if part.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", part.n, part.word))
		}
	}
	if len(parts) == 0 {
		parts = []string{"no change"}
	}
	line := fmt.Sprintf("**Since the last push:** %s", strings.Join(parts, " · "))
	if checks, files := gaps(c.view.Diagnostics); len(checks)+len(files) > 0 {
		line += ". Some checks did not complete, so a finding can show as resolved"
	}
	b.WriteString(line + "\n\n")
}

// baseline is the findings of the last push before this head, or false
// when this head has no push before it. A second run of the same head
// keeps the baseline of the run before it.
func (c *input) baseline() ([]string, bool) {
	switch {
	case c.old == nil:
		return nil, false
	case c.old.HeadSHA != "" && c.old.HeadSHA == c.head():
		return c.old.Since, !c.old.First
	}
	return c.old.Findings, true
}

func (c *input) status(b *strings.Builder, sec sections) {
	parts := []string{"**" + gateText(c.trailer.Gate.Outcome) + "**"}
	switch {
	case sec.blocking:
		parts = append(parts, fmt.Sprintf("%d blocking", sec.count))
	case sec.count > 0:
		parts = append(parts, fmt.Sprintf("%d to review", sec.count))
	}
	if n := len(sec.attacks); n > 0 {
		parts = append(parts, humanize.Count(n, "attack")+" to review")
	}
	coverage := "Checked " + humanize.Count(c.trailer.Summary.Packages, "package")
	if ch := c.view.Changes; c.delta() {
		var changed []string
		if ch.Packages > 0 {
			changed = append(changed, humanize.Count(ch.Packages, "added or upgraded package"))
		}
		if ch.Workflows > 0 {
			changed = append(changed, humanize.Count(ch.Workflows, "changed workflow"))
		}
		coverage = "No package or workflow changed"
		if len(changed) > 0 {
			coverage = "Checked " + strings.Join(changed, " and ")
		}
	}
	if head := c.head(); head != "" {
		coverage += " at " + code(head[:min(7, len(head))])
	}
	parts = append(parts, coverage+".")
	b.WriteString(strings.Join(parts, " · ") + "\n\n")
}

func (c *input) head() string {
	if c.links.Head != "" {
		return c.links.Head
	}
	return c.header.Scan.GitSHA
}

func gateText(o report.GateOutcome) string {
	switch o {
	case report.GateFail:
		return "Gate failed"
	case report.GatePass:
		return "Gate passed"
	}
	return "No gate"
}

// section writes a card for each of the first full groups, and one line
// for each other group.
func (c *input) section(b *strings.Builder, title string, gs []render.Group, l level) {
	if len(gs) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n", title)
	full := min(l.full, len(gs))
	for _, g := range gs[:full] {
		c.card(b, g)
	}
	rest := gs[full:]
	switch {
	case len(rest) == 0:
		return
	case l.lines == 0:
		fmt.Fprintf(b, "%s %s in the full report.\n\n", humanize.Count(len(rest), "more cause"), verb(len(rest), "is", "are"))
		return
	}
	for i, g := range rest {
		if i == l.lines {
			fmt.Fprintf(b, "- %d more in the full report\n", len(rest)-l.lines)
			break
		}
		c.groupLine(b, g)
	}
	b.WriteString("\n")
}

// card writes one group: its lead in full, the other findings by name, and
// one link to the control and one to report a wrong result.
func (c *input) card(b *strings.Builder, g render.Group) {
	f := g.Lead()
	card := render.NewCard(g)
	head := card.Head
	if where := c.placeOf(f); where != "" {
		head += " · " + where
	}
	b.WriteString(head + "\n\n")
	for _, p := range card.Body {
		b.WriteString(p + "\n\n")
	}
	if len(card.Members) > 0 {
		c.open(b, fmt.Sprintf("%d more with this cause", len(g.Findings)-1))
		b.WriteString(strings.Join(card.Members, "\n") + "\n\n")
		c.close(b)
	}
	fmt.Fprintf(b, "[About this control](%s) · [Wrong result?](%s) · %s\n\n", c.docURL(f.ControlID), c.formURL(f), code(f.ID))
}

// groupLine writes one group on one line.
func (c *input) groupLine(b *strings.Builder, g render.Group) {
	f := g.Lead()
	line := fmt.Sprintf("- %s %s%s: %s · %s", code(g.Kind()), code(render.Subject(f)), g.More(), md(render.Title(f), maxField), code(render.Where(f)))
	if gr := f.Gate; gr != nil {
		line += " · " + strings.ToLower(gr.Label()) + " " + md(render.Text(gr.Cause()), maxField)
	}
	fmt.Fprintf(b, "%s · %s\n", line, code(f.ID))
}

// placeOf is the place of a finding with its change in pull request mode.
func (c *input) placeOf(f *finding.Finding) string {
	where := c.where(f)
	if where != "" && f.Change != "" && c.delta() {
		where = strings.ToLower(string(f.Change)) + " in " + where
	}
	return where
}

// details lists the findings that the comment does not show as a group,
// closed, under one heading for each control.
func (c *input) details(b *strings.Builder, sec sections, lines int) {
	fs := sec.rest
	if len(fs) == 0 {
		return
	}
	var kinds []string
	count := map[string]int{}
	var controls []string
	byControl := map[string][]*finding.Finding{}
	for _, f := range fs {
		k := render.Kind(f)
		if count[k] == 0 {
			kinds = append(kinds, k)
		}
		count[k]++
		if _, ok := byControl[f.ControlID]; !ok {
			controls = append(controls, f.ControlID)
		}
		byControl[f.ControlID] = append(byControl[f.ControlID], f)
	}
	var tally []string
	for _, k := range kinds {
		tally = append(tally, fmt.Sprintf("%d %s", count[k], k))
	}
	summary := fmt.Sprintf("%s: %s", humanize.Count(len(fs), "more finding"), strings.Join(tally, ", "))
	if sec.blocking {
		summary = fmt.Sprintf("%s %s: %s", humanize.Count(len(fs), "finding"), verb(len(fs), "does not block", "do not block"), strings.Join(tally, ", "))
	}
	if lines == 0 {
		fmt.Fprintf(b, "%s. The full report has them.\n\n", summary)
		return
	}
	c.open(b, summary)
	n := 0
	for _, id := range controls {
		if n == lines {
			fmt.Fprintf(b, "- %d more in the full report\n\n", len(fs)-lines)
			break
		}
		group := byControl[id]
		fmt.Fprintf(b, "**%s** · %s\n\n", md(c.header.ControlTitle(id), maxField), code(render.Kind(group[0])))
		for _, f := range group {
			if n == lines {
				break
			}
			fmt.Fprintf(b, "- %s: %s\n", code(render.Subject(f)), md(render.Title(f), maxField))
			n++
		}
		b.WriteString("\n")
	}
	c.close(b)
}

func (c *input) footer(b *strings.Builder) {
	parts := []string{fmt.Sprintf("[vet](%s) %s", repoURL, md(c.header.Tool.Version, maxField)), "open source, by SafeDep"}
	if c.links.Run != "" {
		parts = append(parts, fmt.Sprintf("[Full report](%s)", c.links.Run))
	}
	if cmd := c.download(); cmd != "" {
		parts = append(parts, "Report file: "+code(cmd))
	}
	if u := c.policyURL(); u != "" {
		parts = append(parts, fmt.Sprintf("[Policy](%s)", u))
	}
	parts = append(parts,
		fmt.Sprintf("[Wrong result?](%s)", c.formURL(nil)),
		fmt.Sprintf("[Add vet to your repo](%s/blob/%s/docs/github-action.md)", repoURL, c.ref()))
	c.small(b, strings.Join(parts, " · "))
	if c.via != "" {
		c.small(b, c.via)
	}
}

func (c *input) stateBlock() (string, bool) {
	s := state{HeadSHA: c.head(), Findings: ids(c.view.Findings)}
	s.Since, s.First = c.baseline()
	s.First = !s.First
	return encodeState(s)
}

// download is the command that downloads the JSON report of the run into
// the directory reportDir, or "".
func (c *input) download() string {
	if c.artifact == "" || c.links.RunID == "" || c.links.Repository == "" {
		return ""
	}
	return fmt.Sprintf("gh run download %s -R %s -n %s -D %s", c.links.RunID, c.links.Repository, c.artifact, reportDir)
}

// policyURL links the policy file at the base ref that the gate read, or
// returns "" for a policy that is not one file at a base ref.
func (c *input) policyURL() string {
	ref, path, ok := strings.Cut(c.trailer.Gate.Policy, ":")
	if !ok || ref == "" || strings.Contains(path, ", ") || !fs.ValidPath(path) || c.links.Server == "" || c.links.Repository == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/blob/%s/%s", c.links.Server, c.links.Repository, url.PathEscape(strings.TrimPrefix(ref, "origin/")), pathEscape(path))
}

// where is the place of the finding, a link to the file at the head
// commit when the platform is known.
func (c *input) where(f *finding.Finding) string {
	w := render.Where(f)
	if w == "" {
		return ""
	}
	path, line := render.Place(f)
	if path == "" || c.links.NoFiles || c.links.Server == "" || c.links.Repository == "" || c.links.Head == "" || !fs.ValidPath(path) {
		return code(w)
	}
	u := fmt.Sprintf("%s/%s/blob/%s/%s", c.links.Server, c.links.Repository, url.PathEscape(c.links.Head), pathEscape(c.links.Prefix+path))
	if line > 0 {
		u += fmt.Sprintf("#L%d", line)
	}
	if len(u) > maxURL {
		return code(w)
	}
	return fmt.Sprintf("[%s](%s)", code(w), u)
}

// pathEscape escapes each segment of a slash path.
func pathEscape(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// ref is the git ref of the vet docs: the tag of a release build, else
// the v2 branch.
func (c *input) ref() string {
	if tag, ok := github.ReleaseTag(c.header.Tool.Version); ok {
		return tag
	}
	return devRef
}

func (c *input) docURL(control string) string {
	return fmt.Sprintf("%s/blob/%s/docs/controls.md#%s", repoURL, c.ref(), url.PathEscape(control))
}

// formURL opens the false-positive issue form, filled in for f when f is
// not nil. The keys are the field ids of the form.
func (c *input) formURL(f *finding.Finding) string {
	q := url.Values{"template": {formFile}, "version": {c.header.Tool.Version}}
	if f != nil {
		q.Set("control", f.ControlID)
		q.Set("finding", f.ID)
		q.Set("subject", render.SubjectID(f))
	}
	return repoURL + "/issues/new?" + q.Encode()
}

func (c *input) alert(b *strings.Builder, kind string, lines []string) {
	if c.dialect.Alerts {
		fmt.Fprintf(b, "> [!%s]\n", kind)
	} else {
		lines[0] = "**" + strings.ToUpper(kind[:1]) + strings.ToLower(kind[1:]) + ":** " + lines[0]
	}
	for i, l := range lines {
		if i > 0 {
			b.WriteString(">\n")
		}
		b.WriteString("> " + l + "\n")
	}
	b.WriteString("\n")
}

func (c *input) open(b *strings.Builder, summary string) {
	if c.dialect.HTML {
		fmt.Fprintf(b, "<details><summary>%s</summary>\n\n", summary)
		return
	}
	fmt.Fprintf(b, "**%s**\n\n", summary)
}

func (c *input) close(b *strings.Builder) {
	if c.dialect.HTML {
		b.WriteString("</details>\n\n")
	}
}

func (c *input) small(b *strings.Builder, line string) {
	if c.dialect.HTML {
		fmt.Fprintf(b, "<sub>%s</sub>\n\n", line)
		return
	}
	b.WriteString(line + "\n\n")
}

var (
	md   = render.Bounded
	code = render.ShortCode
)

func ids(fs []*finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func capLines(lines []string, n int) []string {
	if len(lines) <= n {
		return lines
	}
	return append(lines[:n:n], fmt.Sprintf("%d more in the full report.", len(lines)-n))
}

func verb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

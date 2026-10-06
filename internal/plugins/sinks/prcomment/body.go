package prcomment

import (
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/report"
)

const (
	// maxChars is the size limit of a GitHub comment.
	maxChars = 65536
	// maxField bounds a name, a title or a path, and maxText a description,
	// so that no single finding fills the comment.
	maxField = 200
	maxText  = 1000
	// maxLines bounds the one-line lists of the last cut level.
	maxLines = 100
	// maxAlerts bounds the lines of an alert.
	maxAlerts = 5

	repoURL  = "https://github.com/safedep/vet"
	devRef   = "v2"
	formFile = "false-positive.yml"
)

// The cut levels, from the full comment to the smallest one. The body
// takes the first level that fits in maxChars.
const (
	cutNone = iota
	cutDetails
	cutState
	cutReview
	cutBlocking
	cutLevels
)

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
	Server, Repository, Head, Run string
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
	attack  func(*finding.Finding) bool
	links   links
	dialect dialect
	// old is the state of the comment that this run edits, or nil.
	old *state
	// via is a footer line of the adapter that posts the comment.
	via string
	// marker is the first line of the comment.
	marker string
}

// body renders the comment at the first cut level that fits. When no
// level fits, it renders the verdict, the status and the footer only.
func (c *input) body() string {
	for level := cutNone; level < cutLevels; level++ {
		if b := c.render(level); utf8.RuneCountInString(b) <= maxChars {
			return b
		}
	}
	blocking, review, rest := c.sections()
	var b strings.Builder
	b.WriteString(c.marker + "\n")
	fmt.Fprintf(&b, "### %s\n\n", c.heading(len(blocking), len(review)+len(rest)))
	c.status(&b, len(blocking), len(review))
	b.WriteString("The findings do not fit in a comment. The full report has them.\n\n")
	c.footer(&b)
	return b.String()
}

func (c *input) delta() bool { return c.header.Scan.Mode == report.ScanModeDelta }

// sections splits the open findings: the findings that fail the gate,
// the critical and high findings to review, and the rest.
func (c *input) sections() (blocking, review, rest []*finding.Finding) {
	failed := c.trailer.Gate.FindingIDs
	for _, f := range c.view.Findings {
		switch {
		case c.trailer.Gate.Outcome == report.GateFail && slices.Contains(failed, f.ID):
			blocking = append(blocking, f)
		case f.Severity.AtLeast(finding.SeverityHigh):
			review = append(review, f)
		default:
			rest = append(rest, f)
		}
	}
	return blocking, review, rest
}

func (c *input) render(level int) string {
	blocking, review, rest := c.sections()
	var b strings.Builder
	b.WriteString(c.marker + "\n")
	fmt.Fprintf(&b, "### %s\n\n", c.heading(len(blocking), len(review)+len(rest)))
	c.caution(&b)
	c.warning(&b)
	c.note(&b)
	c.progress(&b)
	c.status(&b, len(blocking), len(review))
	c.section(&b, "Blocking", blocking, level >= cutBlocking)
	c.section(&b, "Review", review, level >= cutReview)
	c.details(&b, rest, level >= cutDetails)
	c.snippet(&b, append(slices.Clone(blocking), review...))
	c.footer(&b)
	if level < cutState {
		if block, ok := c.stateBlock(); ok {
			b.WriteString(block + "\n")
		}
	}
	return b.String()
}

func (c *input) heading(blocking, other int) string {
	where := "this scan"
	if c.delta() {
		where = "this pull request"
	}
	switch {
	case blocking > 0:
		return fmt.Sprintf("❌ vet: %s %s %s", humanize.Count(blocking, "finding"), verb(blocking, "blocks", "block"), where)
	case other > 0:
		return fmt.Sprintf("⚠️ vet: %s to review in %s", humanize.Count(other, "finding"), where)
	}
	return "✅ vet: no findings in " + where
}

// caution names each attack. An attack needs action before the merge.
func (c *input) caution(b *strings.Builder) {
	var lines []string
	for _, f := range c.view.Findings {
		if c.attack(f) {
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

// warning names the checks that failed open, so a missing finding does
// not look like a clean result.
func (c *input) warning(b *strings.Builder) {
	if len(c.view.Diagnostics) == 0 {
		return
	}
	lines := []string{"Some checks did not complete, so a finding can be missing. Run the job again before you merge."}
	var details []string
	for _, d := range c.view.Diagnostics {
		details = append(details, fmt.Sprintf("%s: %s", code(d.Component), md(render.Text(d.Message), maxField)))
	}
	c.alert(b, "WARNING", append(lines, capLines(details, maxAlerts)...))
}

// note says that the gate used the policy of the base, when the change
// edits the policy.
func (c *input) note(b *strings.Builder) {
	g := c.trailer.Gate
	if !g.PolicyChanged {
		return
	}
	line := "This change edits the policy. The gate uses the policy of the base branch."
	if g.Policy != "" {
		line = fmt.Sprintf("This change edits the policy. The gate uses %s.", code(g.Policy))
	}
	c.alert(b, "NOTE", []string{line})
}

func (c *input) progress(b *strings.Builder) {
	if c.old == nil {
		return
	}
	p := compare(c.baseline(), ids(c.view.Findings), ids(c.view.Suppressed))
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
	if len(c.view.Diagnostics) > 0 {
		line += ". Some checks did not complete, so a finding can show as resolved"
	}
	b.WriteString(line + "\n\n")
}

// baseline is the findings of the last push before this head. A second run
// of the same head keeps the baseline of the run before it.
func (c *input) baseline() []string {
	if c.old.HeadSHA != "" && c.old.HeadSHA == c.head() {
		return c.old.Since
	}
	return c.old.Findings
}

func (c *input) status(b *strings.Builder, blocking, review int) {
	parts := []string{"**" + gateText(c.trailer.Gate.Outcome) + "**"}
	if blocking > 0 {
		parts = append(parts, fmt.Sprintf("%d blocking", blocking))
	}
	if review > 0 {
		parts = append(parts, fmt.Sprintf("%d to review", review))
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

// section writes a card for each finding, or one line each when short.
func (c *input) section(b *strings.Builder, title string, fs []*finding.Finding, short bool) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n", title)
	if short {
		c.lines(b, fs)
		return
	}
	for _, f := range fs {
		c.card(b, f)
	}
}

func (c *input) card(b *strings.Builder, f *finding.Finding) {
	head := fmt.Sprintf("%s: **%s** · `%s`", code(render.Subject(f)), md(render.Title(f), maxField), f.Severity)
	if where := c.where(f); where != "" {
		if f.Change != "" && c.delta() {
			where = strings.ToLower(string(f.Change)) + " in " + where
		}
		head += " · " + where
	}
	b.WriteString(head + "\n\n")
	if f.Description != "" {
		b.WriteString(md(render.Text(f.Description), maxText) + "\n\n")
	}
	if r := f.Remediation; r != nil && r.Summary != "" {
		fmt.Fprintf(b, "**Fix:** %s\n\n", md(render.Text(r.Summary), maxText))
	}
	if r := f.Remediation; r != nil && r.Command != "" {
		fmt.Fprintf(b, "```sh\n%s\n```\n\n", strings.ReplaceAll(render.Truncate(render.Text(r.Command), maxText), "```", "'''"))
	}
	if len(f.Evidence) > 0 {
		fmt.Fprintf(b, "**Evidence:** %s\n\n", md(render.Text(f.Evidence[0].Summary), maxText))
	}
	fmt.Fprintf(b, "[About this check](%s) · [Wrong result?](%s) · `%s`\n\n", c.docURL(f.ControlID), c.formURL(f), f.ID)
}

// lines writes one line for each finding, up to maxLines.
func (c *input) lines(b *strings.Builder, fs []*finding.Finding) {
	for i, f := range fs {
		if i == maxLines {
			fmt.Fprintf(b, "- %d more in the full report\n", len(fs)-maxLines)
			break
		}
		fmt.Fprintf(b, "- `%s` %s: %s · %s · `%s`\n", f.Severity, code(render.Subject(f)), md(render.Title(f), maxField), code(render.Where(f)), f.ID)
	}
	b.WriteString("\n")
}

// details holds the medium and lower findings, closed.
func (c *input) details(b *strings.Builder, fs []*finding.Finding, short bool) {
	if len(fs) == 0 {
		return
	}
	summary := fmt.Sprintf("%d more %s (medium and lower)", len(fs), verb(len(fs), "finding", "findings"))
	if short {
		fmt.Fprintf(b, "%s are in the full report.\n\n", summary)
		return
	}
	c.open(b, summary)
	c.lines(b, fs)
	c.close(b)
}

// snippet shows how a maintainer accepts a finding. vet reads the policy
// of the base branch, so the suppression must merge first.
func (c *input) snippet(b *strings.Builder, fs []*finding.Finding) {
	if len(fs) == 0 {
		return
	}
	c.open(b, "Maintainers: accept a finding")
	b.WriteString("Add a suppression to the policy file. Merge it to the base branch, then run the job again.\n\n")
	fmt.Fprintf(b, "```yaml\nsuppressions:\n  - id: %s\n    reason: Why this finding is acceptable\n```\n\n", fs[0].ID)
	c.close(b)
}

func (c *input) footer(b *strings.Builder) {
	parts := []string{fmt.Sprintf("[vet](%s) %s", repoURL, md(c.header.Tool.Version, maxField)), "open source, by SafeDep"}
	if c.links.Run != "" {
		parts = append(parts, fmt.Sprintf("[Full report](%s)", c.links.Run))
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
	if c.old != nil {
		s.Since = c.baseline()
	}
	return encodeState(s)
}

// where is the place of the finding, a link to the file at the head
// commit when the platform is known.
func (c *input) where(f *finding.Finding) string {
	w := render.Where(f)
	if w == "" {
		return ""
	}
	l := f.Locus
	if l == nil || l.Path == "" || c.links.NoFiles || c.links.Server == "" || c.links.Repository == "" || c.links.Head == "" || !fs.ValidPath(l.Path) {
		return code(w)
	}
	segs := strings.Split(c.links.Prefix+l.Path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	u := fmt.Sprintf("%s/%s/blob/%s/%s", c.links.Server, c.links.Repository, url.PathEscape(c.links.Head), strings.Join(segs, "/"))
	if l.StartLine > 0 {
		u += fmt.Sprintf("#L%d", l.StartLine)
	}
	return fmt.Sprintf("[%s](%s)", code(w), u)
}

// ref is the git ref of the vet docs: the tag of a release build, else
// the v2 branch.
func (c *input) ref() string {
	v := c.header.Tool.Version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) || module.IsPseudoVersion(v) || semver.Build(v) != "" {
		return devRef
	}
	return v
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

// md escapes free text for markdown and bounds it to n runes.
func md(s string, n int) string { return render.Markdown(render.Truncate(s, n)) }

// code puts a name or a path in a code span, bounded to maxField runes.
func code(s string) string { return render.Code(render.Truncate(s, maxField)) }

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

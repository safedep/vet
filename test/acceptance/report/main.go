package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	acc "github.com/safedep/vet/v2/test/acceptance"
)

type Status string

const (
	StatusGap     Status = "gap"
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusSkip    Status = "skip"
	StatusUnknown Status = "unknown"
)

const subtestPrefix = "TestAcceptance/"

type junitReport struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Cases []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string   `xml:"name,attr"`
	Failure *xmlNode `xml:"failure"`
	Skipped *xmlNode `xml:"skipped"`
}

type xmlNode struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type result struct {
	status  Status
	message string
}

func parseJUnit(data []byte) (map[string]result, error) {
	var r junitReport
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse junit: %w", err)
	}
	out := map[string]result{}
	for _, s := range r.Suites {
		for _, c := range s.Cases {
			if !strings.HasPrefix(c.Name, subtestPrefix) {
				continue
			}
			id := strings.TrimPrefix(c.Name, subtestPrefix)
			res := result{status: StatusPass}
			switch {
			case c.Failure != nil:
				res.status = StatusFail
				res.message = snippet(c.Failure)
			case c.Skipped != nil:
				res.status = StatusSkip
				res.message = snippet(c.Skipped)
			}
			out[id] = res
		}
	}
	return out, nil
}

// statusesFromJUnit maps each acceptance subtest id to its status. Parent
// aggregate rows (e.g. "npm/guard") are included; they are not catalog ids, so
// summarize ignores them.
func statusesFromJUnit(data []byte) (map[string]Status, error) {
	res, err := parseJUnit(data)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Status, len(res))
	for id, r := range res {
		out[id] = r.status
	}
	return out, nil
}

// snippet extracts the most useful single line from a gotestsum failure/skip
// body. gotestsum captures the whole `go test` log, whose first lines are the
// "=== RUN" headers and the testscript env dump, not the reason. Prefer the
// testscript assertion line ("... .txtar:NN: <reason>"); fall back to the first
// line that is not a go-test header or env dump.
func snippet(n *xmlNode) string {
	lines := strings.Split(n.Body, "\n")
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if strings.Contains(s, ".txtar:") {
			return truncate(s)
		}
	}
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if s == "" || isTestLogNoise(s) {
			continue
		}
		return truncate(s)
	}
	if m := strings.TrimSpace(n.Message); m != "" && !isTestLogNoise(m) {
		return truncate(m)
	}
	return ""
}

func isTestLogNoise(s string) bool {
	for _, p := range []string{"=== RUN", "=== PAUSE", "=== CONT", "=== NAME", "--- FAIL", "--- PASS", "--- SKIP"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	// The testscript env dump: "testscript.go:NN: WORK=..." then indented KEY=VALUE lines.
	return strings.HasPrefix(s, "testscript.go:") || strings.Contains(s, "=$WORK")
}

func truncate(line string) string {
	const max = 200
	if len(line) > max {
		return line[:max] + "…"
	}
	return line
}

type Row struct {
	G      acc.Guarantee
	Status Status
}

type Summary struct {
	Rows   []Row
	Counts map[Status]int
}

// summarize joins the catalog with the JUnit statuses. An id with a result takes
// that status. An id with no result but a script on disk is unknown (the run did
// not report it), distinct from a gap (no script authored yet).
func summarize(cat *acc.Catalog, st map[string]Status, scripts map[string]bool) Summary {
	sum := Summary{Counts: map[Status]int{}}
	for _, id := range cat.IDs() {
		g, _ := cat.Get(id)
		s := StatusGap
		switch {
		case st[id] != "":
			s = st[id]
		case scripts[id]:
			s = StatusUnknown
		}
		sum.Rows = append(sum.Rows, Row{G: g, Status: s})
		sum.Counts[s]++
	}
	return sum
}

func icon(s Status) string {
	switch s {
	case StatusPass:
		return "✅"
	case StatusFail:
		return "❌"
	case StatusSkip:
		return "⏭️"
	case StatusUnknown:
		return "❓"
	default:
		return "⚪"
	}
}

var tierOrder = []acc.Tier{acc.TierP0, acc.TierP1, acc.TierP2}

// errWriter accumulates the first write error so the report builders stay
// readable while still honoring the errcheck rule on fmt.Fprintf.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

func render(w io.Writer, sum Summary, messages map[string]result) error {
	ew := &errWriter{w: w}
	ew.printf("# vet Acceptance Report\n\n")
	ew.printf("✅ %d pass · ❌ %d fail · ⏭️ %d skip · ❓ %d unknown · ⚪ %d gap\n\n",
		sum.Counts[StatusPass], sum.Counts[StatusFail], sum.Counts[StatusSkip],
		sum.Counts[StatusUnknown], sum.Counts[StatusGap])

	renderTierRollup(ew, sum)

	byCategory := map[string][]Row{}
	categories := []string{}
	for _, r := range sum.Rows {
		if _, seen := byCategory[r.G.Category]; !seen {
			categories = append(categories, r.G.Category)
		}
		byCategory[r.G.Category] = append(byCategory[r.G.Category], r)
	}
	sort.Strings(categories)

	for _, category := range categories {
		ew.printf("## %s\n\n| | Tier | Guarantee | Detail |\n|---|---|---|---|\n", category)
		rows := byCategory[category]
		sortRowsByTier(rows)
		for _, r := range rows {
			detail := r.G.Guarantee
			if r.Status == StatusFail || r.Status == StatusSkip {
				if m, ok := messages[r.G.ID]; ok && m.message != "" {
					detail = fmt.Sprintf("%s — %s", r.G.Guarantee, m.message)
				}
			}
			ew.printf("| %s | %s | `%s` | %s |\n", icon(r.Status), r.G.Tier, r.G.ID, mdCell(detail))
		}
		ew.printf("\n")
	}
	return ew.err
}

func renderTierRollup(ew *errWriter, sum Summary) {
	perTier := map[acc.Tier]map[Status]int{}
	for _, r := range sum.Rows {
		if perTier[r.G.Tier] == nil {
			perTier[r.G.Tier] = map[Status]int{}
		}
		perTier[r.G.Tier][r.Status]++
	}

	ew.printf("| Tier | ✅ | ❌ | ⏭️ | ❓ | ⚪ | coverage |\n|---|---|---|---|---|---|---|\n")
	for _, tier := range tierOrder {
		c := perTier[tier]
		total := c[StatusPass] + c[StatusFail] + c[StatusSkip] + c[StatusUnknown] + c[StatusGap]
		ew.printf("| %s | %d | %d | %d | %d | %d | %d/%d |\n",
			tier, c[StatusPass], c[StatusFail], c[StatusSkip], c[StatusUnknown], c[StatusGap],
			c[StatusPass], total)
	}
	ew.printf("\n")
}

func sortRowsByTier(rows []Row) {
	rank := map[acc.Tier]int{acc.TierP0: 0, acc.TierP1: 1, acc.TierP2: 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].G.Tier != rows[j].G.Tier {
			return rank[rows[i].G.Tier] < rank[rows[j].G.Tier]
		}
		return rows[i].G.ID < rows[j].G.ID
	})
}

func mdCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// loadScriptIDs returns the set of feature ids that have a script on disk. A
// missing scripts directory is not fatal: script-awareness only refines gap vs
// unknown, so the report still renders without it.
func loadScriptIDs(root string) map[string]bool {
	ids, err := acc.DiscoverScripts(root)
	if err != nil {
		log.Printf("discover scripts under %s: %v (gap/unknown split disabled)", root, err)
		return nil
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

func run() error {
	junitPath := flag.String("junit", "", "path to gotestsum JUnit XML")
	catalogPath := flag.String("catalog", "test/acceptance/catalog.yaml", "path to catalog.yaml")
	scriptsPath := flag.String("scripts", "test/acceptance/scripts", "path to the acceptance scripts root")
	flag.Parse()

	cat, err := acc.LoadCatalog(*catalogPath)
	if err != nil {
		return fmt.Errorf("load catalog: %w", err)
	}

	scripts := loadScriptIDs(*scriptsPath)

	// A missing or unparsable JUnit file when one was requested is an incomplete
	// run, not "everything is a gap". Surface it in the report and fail, so it is
	// never mistaken for real zero coverage.
	results := map[string]result{}
	if *junitPath != "" {
		data, rerr := os.ReadFile(*junitPath)
		if rerr != nil {
			return junitError(cat, scripts, fmt.Errorf("read junit %s: %w", *junitPath, rerr))
		}
		if results, err = parseJUnit(data); err != nil {
			return junitError(cat, scripts, fmt.Errorf("parse junit %s: %w", *junitPath, err))
		}
	}

	statuses := make(map[string]Status, len(results))
	for id, r := range results {
		statuses[id] = r.status
	}

	var b strings.Builder
	if err := render(&b, summarize(cat, statuses, scripts), results); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	if _, err := fmt.Fprint(os.Stdout, b.String()); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// junitError writes a visible report banner to stdout (so it reaches the job
// summary) and returns the underlying error so the tool exits non-zero.
func junitError(cat *acc.Catalog, scripts map[string]bool, cause error) error {
	var b strings.Builder
	ew := &errWriter{w: &b}
	ew.printf("> ⚠️ JUnit results unavailable: %s\n>\n", cause)
	ew.printf("> The acceptance run produced no parsable results. Coverage below is unknown, not zero.\n\n")
	if ew.err != nil {
		return fmt.Errorf("%w (and write failed: %v)", cause, ew.err)
	}
	if rerr := render(&b, summarize(cat, nil, scripts), nil); rerr != nil {
		return fmt.Errorf("%w (and render failed: %v)", cause, rerr)
	}
	if _, werr := fmt.Fprint(os.Stdout, b.String()); werr != nil {
		return fmt.Errorf("%w (and write failed: %v)", cause, werr)
	}
	return cause
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

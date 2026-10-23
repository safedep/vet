package prcomment

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/model"
)

// suppression is one entry of the policy snippet that accepts a group.
type suppression struct {
	ID, PURL, Control, Expires string
}

// suppressions accepts the group and no other finding of all. The packages
// of one version with a common name stem, as @pnpm/exe.linux-x64 and
// @pnpm/exe.win32-x64, share one name glob. Each entry must match each
// finding that it is for and no other finding of the control. A glob that
// fails falls back to the exact names, and an exact name that fails, as a
// name with a glob mark or a package with a second advisory, falls back to
// the finding ids. A broad entry hides a real finding. An attack finding,
// and a finding of another subject, get their finding id.
func suppressions(g render.Group, all []*finding.Finding) []suppression {
	lead := g.Lead()
	expires := g.WaitUntilText()
	ids := func(fs []*finding.Finding) []suppression {
		out := make([]suppression, 0, len(fs))
		for _, f := range fs {
			out = append(out, suppression{ID: f.ID, Expires: expires})
		}
		return out
	}
	if lead.Attack != nil {
		return ids(g.Findings)
	}

	// A bucket holds the names of one ecosystem, version and stem, each
	// name with its findings, in group order.
	type bucket struct {
		eco     model.Ecosystem
		version string
		names   []string
		byName  map[string][]*finding.Finding
	}
	var buckets []*bucket
	at := map[string]*bucket{}
	var other []*finding.Finding
	for _, f := range g.Findings {
		id, ok := packageOf(f)
		if !ok {
			other = append(other, f)
			continue
		}
		k := strings.Join([]string{string(id.Ecosystem()), id.RawVersion(), stem(id.RawName())}, "\x00")
		b, ok := at[k]
		if !ok {
			b = &bucket{eco: id.Ecosystem(), version: id.RawVersion(), byName: map[string][]*finding.Finding{}}
			at[k] = b
			buckets = append(buckets, b)
		}
		if _, ok := b.byName[id.RawName()]; !ok {
			b.names = append(b.names, id.RawName())
		}
		b.byName[id.RawName()] = append(b.byName[id.RawName()], f)
	}

	inGroup := make(map[*finding.Finding]bool, len(g.Findings))
	for _, f := range g.Findings {
		inGroup[f] = true
	}
	entry := func(eco model.Ecosystem, name, version string, fs []*finding.Finding) (suppression, bool) {
		id, err := model.NewPackageVersion(eco, name, version)
		if err != nil {
			return suppression{}, false
		}
		s := suppression{PURL: strings.ReplaceAll(id.PURL(), "%2A", "*"), Control: lead.ControlID, Expires: expires}
		return s, exactly(s, fs, inGroup, all)
	}
	var out []suppression
	for _, b := range buckets {
		if len(b.names) > 1 {
			var fs []*finding.Finding
			for _, n := range b.names {
				fs = append(fs, b.byName[n]...)
			}
			if s, ok := entry(b.eco, commonPrefix(b.names)+"*", b.version, fs); ok {
				out = append(out, s)
				continue
			}
		}
		for _, n := range b.names {
			if s, ok := entry(b.eco, n, b.version, b.byName[n]); ok {
				out = append(out, s)
			} else {
				other = append(other, b.byName[n]...)
			}
		}
	}
	return append(out, ids(other)...)
}

func packageOf(f *finding.Finding) (model.PackageVersion, bool) {
	if f.Subject.Package == nil {
		return model.PackageVersion{}, false
	}
	id, err := f.Subject.Package.PackageVersion()
	return id, err == nil
}

// stem is the name up to and with its first ".", "-" or "_" after the last
// "/". Names with one stem can share a glob. A name with no such mark is
// its own stem.
func stem(name string) string {
	base := strings.LastIndex(name, "/") + 1
	if i := strings.IndexAny(name[base:], ".-_"); i >= 0 {
		return name[:base+i+1]
	}
	return name
}

// commonPrefix is the longest common prefix of the names that ends on a
// whole rune.
func commonPrefix(names []string) string {
	p := names[0]
	for _, n := range names[1:] {
		for !strings.HasPrefix(n, p) {
			p = p[:len(p)-1]
		}
	}
	for !utf8.ValidString(p) {
		p = p[:len(p)-1]
	}
	return p
}

// exactly reports whether the PURL of s matches each finding of fs, and no
// finding of the control outside the group.
func exactly(s suppression, fs []*finding.Finding, inGroup map[*finding.Finding]bool, all []*finding.Finding) bool {
	p, err := model.ParsePackagePattern(s.PURL)
	if err != nil {
		return false
	}
	for _, f := range fs {
		if id, ok := packageOf(f); !ok || !p.Matches(id) {
			return false
		}
	}
	for _, f := range all {
		if f.ControlID != s.Control || inGroup[f] {
			continue
		}
		if id, ok := packageOf(f); ok && p.Matches(id) {
			return false
		}
	}
	return true
}

// snippet shows how a maintainer accepts each group that the comment shows.
// vet reads the policy of the base branch, so the suppression must merge
// first.
func (c *input) snippet(b *strings.Builder, gs []render.Group) {
	if len(gs) == 0 {
		return
	}
	c.open(b, "Maintainers: accept "+verb(len(gs), "this cause", "these causes"))
	file := "the policy file"
	if _, path, ok := strings.Cut(c.trailer.Gate.Policy, ":"); ok && c.policyURL() != "" {
		file = code(path)
	}
	fmt.Fprintf(b, "Add the entries to %s on the base branch, then run the job again. Each entry matches no other finding of this scan. An entry with no expires stays until you remove it.\n\n", file)
	b.WriteString("```yaml\nsuppressions:\n")
	for _, g := range gs {
		fmt.Fprintf(b, "  # %s\n", yamlComment(render.Subject(g.Lead())+g.More()))
		entries := suppressions(g, c.view.Findings)
		for _, e := range entries[:min(len(entries), maxEntries)] {
			var lines []string
			for _, kv := range [][2]string{{"id", e.ID}, {"purl", e.PURL}, {"control", e.Control}, {"reason", "Why this is acceptable"}, {"expires", e.Expires}} {
				if kv[1] != "" {
					lines = append(lines, kv[0]+": "+kv[1])
				}
			}
			for i, l := range lines {
				mark := "  "
				if i == 0 {
					mark = "- "
				}
				fmt.Fprintf(b, "  %s%s\n", mark, l)
			}
		}
		if n := len(entries) - maxEntries; n > 0 {
			fmt.Fprintf(b, "  # %d more entries. The agent block and the report have the finding ids.\n", n)
		}
	}
	b.WriteString("```\n\n")
	c.close(b)
}

// yamlComment keeps untrusted text on one comment line inside the code
// block.
func yamlComment(s string) string {
	return strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(render.Truncate(s, maxField))
}

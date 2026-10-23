package render

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/safedep/vet/v2/finding"
)

// Group is the findings of one cause: one control, one gate record and one
// fix. A developer acts on a group once. Findings[0] is the lead.
type Group struct {
	Findings []*finding.Finding
}

// Lead is the finding that names the group.
func (g Group) Lead() *finding.Finding { return g.Findings[0] }

// Severity is the highest severity in the group.
func (g Group) Severity() finding.Severity {
	s := g.Lead().Severity
	for _, f := range g.Findings[1:] {
		if f.Severity.Rank() > s.Rank() {
			s = f.Severity
		}
	}
	return s
}

// WaitUntil is the latest end of a wait in the group, as the end of a
// cooldown. The group ends only when each finding ends.
func (g Group) WaitUntil() (time.Time, bool) {
	var until time.Time
	for _, f := range g.Findings {
		if r := f.Remediation; r != nil && r.WaitUntil != nil && r.WaitUntil.After(until) {
			until = *r.WaitUntil
		}
	}
	return until, !until.IsZero()
}

// WaitUntilText is the latest end of a wait in the group in RFC 3339, for a
// policy expiry or an agent, or "".
func (g Group) WaitUntilText() string {
	if until, ok := g.WaitUntil(); ok {
		return until.UTC().Format(time.RFC3339)
	}
	return ""
}

// Groups puts the findings of one cause together. The key is the control,
// the gate record, the fix and the file to edit. An attack finding, or a finding with no fix,
// is a group of its own, so that a fold never hides an attack. Groups come
// in this order: attacks, then the highest severity, then the most
// findings, then the order of their first finding.
func Groups(fs []*finding.Finding) []Group {
	var out []Group
	at := map[string]int{}
	for _, f := range fs {
		k, ok := groupKey(f)
		if !ok {
			out = append(out, Group{Findings: []*finding.Finding{f}})
			continue
		}
		if i, ok := at[k]; ok {
			out[i].Findings = append(out[i].Findings, f)
			continue
		}
		at[k] = len(out)
		out = append(out, Group{Findings: []*finding.Finding{f}})
	}
	for _, g := range out {
		slices.SortStableFunc(g.Findings, leadFirst)
		slices.SortStableFunc(g.Findings[1:], func(a, b *finding.Finding) int {
			return cmp.Or(cmp.Compare(Subject(a), Subject(b)), cmp.Compare(a.ID, b.ID))
		})
	}
	slices.SortStableFunc(out, func(a, b Group) int {
		if aa, ba := a.Lead().Attack != nil, b.Lead().Attack != nil; aa != ba {
			if aa {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(b.Severity().Rank(), a.Severity().Rank()); c != 0 {
			return c
		}
		return cmp.Compare(len(b.Findings), len(a.Findings))
	})
	return out
}

func groupKey(f *finding.Finding) (string, bool) {
	r := f.Remediation
	if f.Attack != nil || r == nil || r.Summary == "" {
		return "", false
	}
	gate := ""
	if g := f.Gate; g != nil {
		gate = strings.Join([]string{string(g.Action), g.FailOn, strings.Join(g.Rules, ","), strings.Join(g.Broken, ",")}, "\x01")
	}
	// The file to edit is in the key, so that one cause has one place to
	// edit, and one annotation marks it.
	path, _ := Place(f)
	return strings.Join([]string{f.ControlID, gate, r.Summary, r.Command, path}, "\x00"), true
}

// leadFirst puts the finding that names a group first: a direct dependency,
// then the shortest name, then the first PURL, then the most severe. A
// release with platform packages has the main package as its lead.
func leadFirst(a, b *finding.Finding) int {
	pa, pb := a.Subject.Package, b.Subject.Package
	if pa != nil && pb != nil {
		if pa.Direct != pb.Direct {
			if pa.Direct {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(len(pa.RawName), len(pb.RawName)); c != 0 {
			return c
		}
		if c := cmp.Compare(pa.PURL, pb.PURL); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

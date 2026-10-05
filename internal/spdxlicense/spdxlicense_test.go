package spdxlicense

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name       string
		values     []string
		expression string
		ids        bool
		unknown    []string
		none       bool
	}{
		{"one id", []string{"MIT"}, "MIT", true, nil, false},
		{"lower case id", []string{"mit"}, "MIT", true, nil, false},
		{"two ids join with AND", []string{"MIT", "Apache-2.0"}, "MIT AND Apache-2.0", true, nil, false},
		{"one expression", []string{"MIT OR Apache-2.0"}, "MIT OR Apache-2.0", false, nil, false},
		{"lower case operators", []string{"mit or apache-2.0"}, "MIT OR Apache-2.0", false, nil, false},
		{"an expression and an id", []string{"MIT OR GPL-3.0-only", "BSD-3-Clause"}, "(MIT OR GPL-3.0-only) AND BSD-3-Clause", false, nil, false},
		{"precedence", []string{"MIT OR ISC AND BSD-3-Clause"}, "MIT OR (ISC AND BSD-3-Clause)", false, nil, false},
		{"deprecated id", []string{"GPL-3.0"}, "GPL-3.0-only", false, nil, false},
		{"deprecated plus", []string{"GPL-2.0+"}, "GPL-2.0-or-later", false, nil, false},
		{"plus", []string{"EUPL-1.2+"}, "EUPL-1.2+", false, nil, false},
		{"deprecated id with an exception", []string{"GPL-2.0-with-classpath-exception"}, "GPL-2.0-only WITH Classpath-exception-2.0", false, nil, false},
		{"with", []string{"Apache-2.0 WITH LLVM-exception"}, "Apache-2.0 WITH LLVM-exception", false, nil, false},
		{"license ref", []string{"LicenseRef-acme"}, "LicenseRef-acme", false, nil, false},
		{"free text", []string{"Apache 2.0"}, "", false, []string{"Apache 2.0"}, false},
		{"unknown exception", []string{"MIT WITH nope"}, "", false, []string{"MIT WITH nope"}, false},
		{"syntax error", []string{"MIT OR"}, "", false, []string{"MIT OR"}, false},
		{"free text and an id", []string{"MIT", "BSD"}, "MIT", false, []string{"BSD"}, false},
		{"no assertion", []string{"NOASSERTION"}, "", false, []string{"NOASSERTION"}, false},
		{"none", []string{"NONE"}, "", false, nil, true},
		{"no value", nil, "", false, nil, false},
		{"blank values", []string{" ", ""}, "", false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Parse(tc.values)
			assert.Equal(t, tc.expression, d.Expression)
			assert.Equal(t, tc.ids, d.IDs)
			assert.Equal(t, tc.unknown, d.Unknown)
			assert.Equal(t, tc.none, d.None)
		})
	}
}

func TestParseLimits(t *testing.T) {
	long := strings.Repeat("(MIT OR ISC) AND ", 70) + "MIT"
	require.Greater(t, len(long), maxValueLen)
	start := time.Now()
	d := Parse([]string{long})
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, []string{long}, d.Unknown, "a value over the length limit is unknown")

	deep := strings.Repeat("(", maxDepth+2) + "MIT" + strings.Repeat(")", maxDepth+2)
	assert.Equal(t, []string{deep}, Parse([]string{deep}).Unknown)

	wide := strings.Repeat("(MIT OR ISC) AND ", 40) + "MIT"
	require.LessOrEqual(t, len(wide), maxValueLen)
	start = time.Now()
	p, err := NewPolicy([]string{"MIT"}, []string{"ISC"})
	require.NoError(t, err)
	assert.Equal(t, Pass, p.Check(Parse([]string{wide})).Verdict)
	assert.True(t, Equal([]string{wide}, []string{wide}))
	assert.Less(t, time.Since(start), time.Second, "evaluation is linear")
}

func TestKnown(t *testing.T) {
	assert.True(t, Parse([]string{"MIT"}).Known())
	assert.True(t, Parse([]string{"NONE"}).Known())
	assert.False(t, Parse(nil).Known())
	assert.False(t, Parse([]string{"NOASSERTION"}).Known())
	assert.False(t, Parse([]string{"MIT", "BSD"}).Known())
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name        string
		allow, deny []string
		values      []string
		want        Verdict
		denied      []string
	}{
		{"allow an id", []string{"MIT"}, nil, []string{"MIT"}, Pass, nil},
		{"allow a choice of OR", []string{"MIT"}, nil, []string{"MIT OR GPL-3.0-only"}, Pass, nil},
		{"allow needs each part of AND", []string{"MIT"}, nil, []string{"MIT AND GPL-3.0-only"}, NotAllowed, nil},
		{"allow both parts of AND", []string{"MIT", "GPL-3.0-only"}, nil, []string{"MIT AND GPL-3.0-only"}, Pass, nil},
		{"allow a nested expression", []string{"MIT", "BSD-3-Clause"}, nil, []string{"(MIT OR GPL-3.0-only) AND BSD-3-Clause"}, Pass, nil},
		{"two values join with AND", []string{"MIT"}, nil, []string{"MIT", "Apache-2.0"}, NotAllowed, nil},
		{"allow lower case", []string{"mit"}, nil, []string{"MIT"}, Pass, nil},
		{"allow a deprecated id", []string{"GPL-3.0-only"}, nil, []string{"GPL-3.0"}, Pass, nil},
		{"allow or-later with a later version", []string{"GPL-3.0-only"}, nil, []string{"GPL-2.0+"}, Pass, nil},
		{"allow or-later needs a version in range", []string{"GPL-2.0-only"}, nil, []string{"GPL-3.0-or-later"}, NotAllowed, nil},
		{"allow entry or-later is exact", []string{"GPL-2.0-or-later"}, nil, []string{"GPL-3.0-only"}, NotAllowed, nil},
		{"WITH needs its own entry", []string{"GPL-2.0-only"}, nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, NotAllowed, nil},
		{"allow the WITH term", []string{"gpl-2.0-only with classpath-exception-2.0"}, nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, Pass, nil},
		{"license ref needs its own entry", []string{"MIT"}, nil, []string{"LicenseRef-acme"}, NotAllowed, nil},
		{"allow a license ref", []string{"LicenseRef-acme"}, nil, []string{"LicenseRef-acme"}, Pass, nil},
		{"none fails an allow list", []string{"MIT"}, nil, []string{"NONE"}, NotAllowed, nil},
		{"none is unknown to a deny list", nil, []string{"GPL-3.0-only"}, []string{"NONE"}, Unknown, nil},
		{"none beside an id passes a deny list", nil, []string{"GPL-3.0-only"}, []string{"MIT", "NONE"}, Pass, nil},
		{"unknown with an allow list", []string{"MIT"}, nil, []string{"NOASSERTION"}, Unknown, nil},
		{"free text with an allow list", []string{"MIT"}, nil, []string{"Apache 2.0"}, Unknown, nil},
		{"no data with an allow list", []string{"MIT"}, nil, nil, Unknown, nil},
		{"allowed part beside an unknown value", []string{"MIT"}, nil, []string{"MIT", "BSD"}, Unknown, nil},
		{"rejected part beside an unknown value", []string{"MIT"}, nil, []string{"GPL-3.0-only", "non-standard"}, NotAllowed, nil},
		{"rejected part beside no assertion", []string{"MIT"}, nil, []string{"GPL-3.0-only", "NOASSERTION"}, NotAllowed, nil},
		{"deny an id", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"deny a deprecated id", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0"}, Denied, []string{"GPL-3.0-only"}},
		{"deny entry with a deprecated id", nil, []string{"GPL-3.0"}, []string{"GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"deny lets a choice pass", nil, []string{"GPL-3.0-only"}, []string{"MIT OR GPL-3.0-only"}, Pass, nil},
		{"deny AND", nil, []string{"GPL-3.0-only"}, []string{"MIT AND GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"deny each choice", nil, []string{"GPL-3.0-only", "AGPL-3.0-only"}, []string{"GPL-3.0-only OR AGPL-3.0-only"}, Denied, []string{"AGPL-3.0-only", "GPL-3.0-only"}},
		{"deny in a nested expression", nil, []string{"BSD-3-Clause"}, []string{"(MIT OR GPL-3.0-only) AND BSD-3-Clause"}, Denied, []string{"BSD-3-Clause"}},
		{"deny the second of two values", nil, []string{"GPL-3.0-only"}, []string{"MIT", "GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"deny is case insensitive", nil, []string{"gpl-3.0-only"}, []string{"GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"deny plus", nil, []string{"GPL-2.0+"}, []string{"GPL-2.0-or-later"}, Denied, []string{"GPL-2.0-or-later"}},
		{"deny of the base does not deny WITH", nil, []string{"GPL-2.0-only"}, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, Pass, nil},
		{"deny the WITH term", nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, Denied, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}},
		{"deny a deprecated WITH id", nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, []string{"GPL-2.0-with-classpath-exception"}, Denied, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}},
		{"deny a deprecated variant", nil, []string{"BSD-2-Clause-Views"}, []string{"BSD-2-Clause-FreeBSD"}, Denied, []string{"BSD-2-Clause-Views"}},
		{"deny a deprecated duplicate", nil, []string{"BSD-2-Clause"}, []string{"BSD-2-Clause-NetBSD"}, Denied, []string{"BSD-2-Clause"}},
		{"deny plus with no later version", nil, []string{"EUPL-1.2"}, []string{"EUPL-1.2+"}, Denied, []string{"EUPL-1.2+"}},
		{"deny plus of an id with no version", nil, []string{"MIT"}, []string{"MIT+"}, Denied, []string{"MIT+"}},
		{"deny plus with an allowed later version", nil, []string{"EUPL-1.1"}, []string{"EUPL-1.1+"}, Pass, nil},
		{"deny or-later when each version is denied", nil, []string{"GPL-2.0-only", "GPL-3.0-only"}, []string{"GPL-2.0-or-later"}, Denied, []string{"GPL-2.0-or-later"}},
		{"deny or-later with an allowed later version", nil, []string{"GPL-2.0-only"}, []string{"GPL-2.0-or-later"}, Pass, nil},
		{"deny or-later of an only id", nil, []string{"GPL-3.0-only"}, []string{"GPL-2.0-or-later"}, Pass, nil},
		{"a choice never makes deny stricter", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only OR GPL-2.0-or-later"}, Pass, nil},
		{"deny decides beside an unknown value", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only", "BSD"}, Denied, []string{"GPL-3.0-only"}},
		{"deny passes a free text value", nil, []string{"GPL-3.0-only"}, []string{"BSD"}, Unknown, nil},
		{"deny goes first", []string{"MIT"}, []string{"GPL-3.0-only"}, []string{"MIT AND GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"one choice must satisfy both lists", []string{SetOSIApproved}, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only OR SSPL-1.0"}, NotAllowed, nil},
		{"a choice that satisfies both lists", []string{SetOSIApproved}, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only OR MIT"}, Pass, nil},
		{"or-later with each allowed version denied", []string{"GPL-2.0-only", "GPL-3.0-only"}, []string{"GPL-3.0-only"}, []string{"GPL-3.0-or-later OR SSPL-1.0"}, NotAllowed, nil},
		{"osi set allows MIT", []string{SetOSIApproved}, nil, []string{"MIT"}, Pass, nil},
		{"osi set does not allow WTFPL", []string{SetOSIApproved}, nil, []string{"WTFPL"}, NotAllowed, nil},
		{"fsf set allows WTFPL", []string{SetFSFLibre}, nil, []string{"WTFPL"}, Pass, nil},
		{"either set allows WTFPL", []string{SetOSIApprovedOrFSF}, nil, []string{"WTFPL"}, Pass, nil},
		{"osi set allows a deprecated id", []string{SetOSIApproved}, nil, []string{"GPL-3.0"}, Pass, nil},
		{"osi set does not allow a WITH term", []string{SetOSIApproved}, nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, NotAllowed, nil},
		{"osi set holds no WITH term of a deprecated id", []string{SetOSIApproved}, nil, []string{"GPL-3.0-only WITH GCC-exception-3.1"}, NotAllowed, nil},
		{"osi set and a deprecated variant", []string{SetOSIApproved}, nil, []string{"BSD-2-Clause-FreeBSD"}, NotAllowed, nil},
		{"deny the font exception", nil, []string{"GPL-2.0-only WITH Font-exception-2.0"}, []string{"GPL-2.0-with-font-exception"}, Denied, []string{"GPL-2.0-only WITH Font-exception-2.0"}},
		{"deny a GFDL variant or-later", nil, []string{"GFDL-1.1-invariants-only", "GFDL-1.2-invariants-only", "GFDL-1.3-invariants-only"}, []string{"GFDL-1.1-invariants-or-later"}, Denied, []string{"GFDL-1.1-invariants-or-later"}},
		{"plus on a license ref is not SPDX", nil, []string{"LicenseRef-a"}, []string{"LicenseRef-a+"}, Unknown, nil},
		{"no lists", nil, nil, []string{"GPL-3.0-only"}, Pass, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPolicy(tc.allow, tc.deny)
			require.NoError(t, err)
			got := p.Check(Parse(tc.values))
			assert.Equal(t, tc.want, got.Verdict)
			assert.Equal(t, tc.denied, got.Denied)
		})
	}
}

func TestNewPolicyRejectsEntries(t *testing.T) {
	for _, e := range []string{"GPL", "MIT OR Apache-2.0", "MIT AND GPL-3.0-only", "osi", "Apache 2.0", "", "MIT WITH nope", "LicenseRef-", "LicenseRef-a,b", "LicenseRef-a+", "DocumentRef-x"} {
		t.Run(e, func(t *testing.T) {
			_, err := NewPolicy([]string{e}, nil)
			assert.ErrorContains(t, err, "allow:")
			_, err = NewPolicy(nil, []string{e})
			assert.ErrorContains(t, err, "deny:")
		})
	}
	_, err := NewPolicy([]string{"mit", "GPL-2.0+", "LicenseRef-acme", "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2", "GPL-2.0-only with Classpath-exception-2.0", SetFSFLibre}, nil)
	assert.NoError(t, err)
}

func TestEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"same id", []string{"MIT"}, []string{"MIT"}, true},
		{"case", []string{"mit"}, []string{"MIT"}, true},
		{"order of OR", []string{"MIT OR Apache-2.0"}, []string{"Apache-2.0 OR MIT"}, true},
		{"nested OR", []string{"MIT OR (ISC OR Apache-2.0)"}, []string{"Apache-2.0 OR ISC OR MIT"}, true},
		{"deprecated id", []string{"GPL-3.0"}, []string{"GPL-3.0-only"}, true},
		{"plus", []string{"GPL-2.0+"}, []string{"GPL-2.0-or-later"}, true},
		{"order of values", []string{"MIT", "Apache-2.0"}, []string{"Apache-2.0", "MIT"}, true},
		{"OR is not AND", []string{"MIT OR Apache-2.0"}, []string{"MIT AND Apache-2.0"}, false},
		{"OR is not AND in one license group", []string{"GPL-2.0-or-later AND GPL-3.0-only"}, []string{"GPL-2.0-or-later OR GPL-3.0-only"}, false},
		{"other id", []string{"MIT"}, []string{"Apache-2.0"}, false},
		{"only is not or-later", []string{"GPL-2.0-only"}, []string{"GPL-2.0-or-later"}, false},
		{"none is not an id", []string{"NONE"}, []string{"MIT"}, false},
		{"none", []string{"NONE"}, []string{"none"}, true},
		{"none and an id", []string{"NONE"}, []string{"NONE", "MIT"}, false},
		{"repeated operand", []string{"(MIT AND MIT) OR Apache-2.0"}, []string{"MIT OR Apache-2.0"}, true},
		{"nested group of one", []string{"((MIT)) OR (ISC OR (Apache-2.0))"}, []string{"Apache-2.0 OR ISC OR MIT"}, true},
		{"free text", []string{"Apache 2.0"}, []string{"Apache 2.0"}, true},
		{"free text and id", []string{"Apache 2.0"}, []string{"Apache-2.0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Equal(tc.a, tc.b))
		})
	}
}

func TestRestricted(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   bool
	}{
		{"source available", []string{"SSPL-1.0"}, true},
		{"business source", []string{"BUSL-1.1"}, true},
		{"non-commercial", []string{"CC-BY-NC-SA-4.0"}, true},
		{"no derived works", []string{"CC-BY-ND-4.0"}, true},
		{"AND", []string{"MIT AND Elastic-2.0"}, true},
		{"two values", []string{"MIT", "PolyForm-Noncommercial-1.0.0"}, true},
		{"a choice that does not limit use", []string{"MIT OR SSPL-1.0"}, false},
		{"permissive", []string{"MIT"}, false},
		{"permissive with no SPDX flag", []string{"PSF-2.0"}, false},
		{"attribution only", []string{"CC-BY-4.0"}, false},
		{"license ref", []string{"LicenseRef-acme"}, false},
		{"none", []string{"NONE"}, false},
		{"free text", []string{"Apache 2.0"}, false},
		{"no value", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Restricted(Parse(tc.values)))
		})
	}
}

func TestNoLicense(t *testing.T) {
	assert.True(t, Parse([]string{"NONE"}).NoLicense())
	assert.False(t, Parse([]string{"NONE", "MIT"}).NoLicense())
	assert.False(t, Parse(nil).NoLicense())
}

// The embedded list and go-spdx must come from one SPDX License List, so a
// set never names an id that go-spdx does not know. go generate rewrites
// the list from the go-spdx module after a go-spdx upgrade.
func TestListMatchesGoSPDX(t *testing.T) {
	var active, deprecated []string
	for _, l := range list.Licenses {
		if l.Deprecated {
			deprecated = append(deprecated, l.ID)
		} else {
			active = append(active, l.ID)
		}
	}
	assert.ElementsMatch(t, spdxlicenses.GetLicenses(), active, "run go generate ./internal/spdxlicense")
	assert.ElementsMatch(t, spdxlicenses.GetDeprecated(), deprecated, "run go generate ./internal/spdxlicense")
	assert.NotEmpty(t, list.Version)
	assert.True(t, strings.HasPrefix(ListVersion(), list.Version))
}

func TestSuccessors(t *testing.T) {
	for old, t2 := range successors {
		t.Run(old, func(t *testing.T) {
			l, ok := ids[strings.ToLower(old)]
			require.True(t, ok)
			assert.True(t, l.Deprecated)
			_, ok = ActiveID(t2.id)
			assert.True(t, ok, "%s is an active id", t2.id)
			if t2.exception != "" {
				assert.Equal(t, t2.exception, exceptions[strings.ToLower(t2.exception)])
			}
		})
	}
}

// Each deprecated id maps to a successor, or is on the list of ids that
// keep their own name.
func TestEachDeprecatedIDHasASuccessor(t *testing.T) {
	for _, l := range list.Licenses {
		if !l.Deprecated {
			continue
		}
		t.Run(l.ID, func(t *testing.T) {
			got, ok := canonical(l.ID)
			require.True(t, ok)
			if slices.Contains(keptDeprecated, l.ID) {
				assert.Equal(t, term{id: l.ID}, got)
				return
			}
			assert.NotEqual(t, l.ID, got.id)
			_, active := ActiveID(got.id)
			assert.True(t, active, "%s maps to the active id %s", l.ID, got.id)
		})
	}
}

func TestLaterVersions(t *testing.T) {
	assert.Equal(t, []string{"GFDL-1.1-invariants-only", "GFDL-1.2-invariants-only", "GFDL-1.3-invariants-only"}, laterVersions("GFDL-1.1-invariants-or-later"))
	assert.Equal(t, []string{"GPL-2.0-only", "GPL-3.0-only"}, laterVersions("GPL-2.0-or-later"))
	assert.Equal(t, []string{"EUPL-1.2"}, laterVersions("EUPL-1.2"))
	assert.Equal(t, []string{"EUPL-1.1", "EUPL-1.2"}, laterVersions("EUPL-1.1"))
	assert.Equal(t, []string{"MIT"}, laterVersions("MIT"))
}

func TestSets(t *testing.T) {
	osi, _ := setIDs(SetOSIApproved)
	fsf, _ := setIDs(SetFSFLibre)
	either, _ := setIDs(SetOSIApprovedOrFSF)
	assert.Contains(t, osi, "Apache-2.0")
	assert.NotContains(t, osi, "WTFPL")
	assert.Contains(t, fsf, "WTFPL")
	assert.Subset(t, either, osi)
	assert.Subset(t, either, fsf)
	assert.True(t, slices.IsSorted(either))
}

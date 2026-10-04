package spdxlicense

import (
	"slices"
	"strings"
	"testing"

	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   Declared
	}{
		{"one id", []string{"MIT"}, Declared{Expression: "MIT", IDs: true}},
		{"lower case id", []string{"mit"}, Declared{Expression: "MIT", IDs: true}},
		{"two ids join with AND", []string{"MIT", "Apache-2.0"}, Declared{Expression: "MIT AND Apache-2.0", IDs: true}},
		{"one expression", []string{"MIT OR Apache-2.0"}, Declared{Expression: "MIT OR Apache-2.0"}},
		{"an expression and an id", []string{"MIT OR GPL-3.0-only", "BSD-3-Clause"}, Declared{Expression: "(MIT OR GPL-3.0-only) AND BSD-3-Clause"}},
		{"deprecated id", []string{"GPL-3.0"}, Declared{Expression: "GPL-3.0"}},
		{"license ref", []string{"LicenseRef-acme"}, Declared{Expression: "LicenseRef-acme"}},
		{"free text", []string{"Apache 2.0"}, Declared{Unknown: []string{"Apache 2.0"}}},
		{"free text and an id", []string{"MIT", "BSD"}, Declared{Expression: "MIT", Unknown: []string{"BSD"}}},
		{"no assertion", []string{"NOASSERTION"}, Declared{Unknown: []string{"NOASSERTION"}}},
		{"none", []string{"NONE"}, Declared{None: true}},
		{"no value", nil, Declared{}},
		{"blank values", []string{" ", ""}, Declared{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Parse(tc.values))
		})
	}
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
		{"allow lower case", []string{"MIT"}, nil, []string{"mit"}, Pass, nil},
		{"allow a deprecated id", []string{"GPL-3.0-only"}, nil, []string{"GPL-3.0"}, Pass, nil},
		{"allow or-later with a later version", []string{"GPL-3.0-only"}, nil, []string{"GPL-2.0+"}, Pass, nil},
		{"WITH needs its own entry", []string{"GPL-2.0-only"}, nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, NotAllowed, nil},
		{"allow the WITH term", []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, Pass, nil},
		{"license ref needs its own entry", []string{"MIT"}, nil, []string{"LicenseRef-acme"}, NotAllowed, nil},
		{"allow a license ref", []string{"LicenseRef-acme"}, nil, []string{"LicenseRef-acme"}, Pass, nil},
		{"none fails an allow list", []string{"MIT"}, nil, []string{"NONE"}, NotAllowed, nil},
		{"none passes a deny list", nil, []string{"GPL-3.0-only"}, []string{"NONE"}, Pass, nil},
		{"unknown with an allow list", []string{"MIT"}, nil, []string{"NOASSERTION"}, Unknown, nil},
		{"free text with an allow list", []string{"MIT"}, nil, []string{"Apache 2.0"}, Unknown, nil},
		{"no data with an allow list", []string{"MIT"}, nil, nil, Unknown, nil},
		{"deny an id", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"deny a deprecated id", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0"}, Denied, []string{"GPL-3.0"}},
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
		{"or-later does not avoid a denied only", nil, []string{"GPL-2.0-only"}, []string{"MIT AND GPL-2.0-only AND GPL-2.0-or-later"}, Denied, []string{"GPL-2.0-only"}},
		{"deny decides beside an unknown value", nil, []string{"GPL-3.0-only"}, []string{"GPL-3.0-only", "BSD"}, Denied, []string{"GPL-3.0-only"}},
		{"deny passes a free text value", nil, []string{"GPL-3.0-only"}, []string{"BSD"}, Unknown, nil},
		{"deny goes first", []string{"MIT"}, []string{"GPL-3.0-only"}, []string{"MIT AND GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"osi set allows MIT", []string{SetOSIApproved}, nil, []string{"MIT"}, Pass, nil},
		{"osi set does not allow WTFPL", []string{SetOSIApproved}, nil, []string{"WTFPL"}, NotAllowed, nil},
		{"fsf set allows WTFPL", []string{SetFSFLibre}, nil, []string{"WTFPL"}, Pass, nil},
		{"either set allows WTFPL", []string{SetOSIApprovedOrFSF}, nil, []string{"WTFPL"}, Pass, nil},
		{"osi set allows a deprecated id", []string{SetOSIApproved}, nil, []string{"GPL-3.0"}, Pass, nil},
		{"osi set does not allow a WITH term", []string{SetOSIApproved}, nil, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, NotAllowed, nil},
		{"no lists", nil, nil, []string{"GPL-3.0-only"}, Pass, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPolicy(tc.allow, tc.deny)
			require.NoError(t, err)
			got, err := p.Check(Parse(tc.values))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Verdict)
			assert.Equal(t, tc.denied, got.Denied)
		})
	}
}

func TestNewPolicyRejectsEntries(t *testing.T) {
	for _, e := range []string{"GPL", "MIT OR Apache-2.0", "MIT AND GPL-3.0-only", "osi", "Apache 2.0", ""} {
		t.Run(e, func(t *testing.T) {
			_, err := NewPolicy([]string{e}, nil)
			assert.ErrorContains(t, err, "allow:")
			_, err = NewPolicy(nil, []string{e})
			assert.ErrorContains(t, err, "deny:")
		})
	}
	_, err := NewPolicy([]string{"mit", "GPL-2.0+", "LicenseRef-acme", "GPL-2.0-only WITH Classpath-exception-2.0", SetFSFLibre}, nil)
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
		{"deprecated id", []string{"GPL-3.0"}, []string{"GPL-3.0-only"}, true},
		{"plus", []string{"GPL-2.0+"}, []string{"GPL-2.0-or-later"}, true},
		{"order of values", []string{"MIT", "Apache-2.0"}, []string{"Apache-2.0", "MIT"}, true},
		{"OR is not AND", []string{"MIT OR Apache-2.0"}, []string{"MIT AND Apache-2.0"}, false},
		{"other id", []string{"MIT"}, []string{"Apache-2.0"}, false},
		{"only is not or-later", []string{"GPL-2.0-only"}, []string{"GPL-2.0-or-later"}, false},
		{"free text", []string{"Apache 2.0"}, []string{"Apache 2.0"}, true},
		{"free text and id", []string{"Apache 2.0"}, []string{"Apache-2.0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Equal(tc.a, tc.b))
		})
	}
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

func TestReplacement(t *testing.T) {
	assert.Equal(t, "GPL-3.0-only", replacement["gpl-3.0"])
	assert.Equal(t, "LGPL-2.1-only", replacement["lgpl-2.1"])
	assert.NotContains(t, replacement, "mit")
	assert.True(t, strings.HasPrefix(ListVersion(), list.Version))
}

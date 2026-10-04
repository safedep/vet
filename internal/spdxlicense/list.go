// Package spdxlicense reads the license of a package as an SPDX license
// expression (SPDX 2.3 Annex D), and checks it against allow and deny
// lists. It parses the expression itself, in linear time, and takes the
// license and exception ids from the SPDX License List of the go-spdx
// version that go.mod pins, with the OSI and FSF flags.
package spdxlicense

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
)

//go:generate go run ./internal/gen

//go:embed list.json
var listJSON []byte

type listEntry struct {
	ID         string `json:"id"`
	Deprecated bool   `json:"deprecated"`
	OSI        bool   `json:"osi"`
	FSF        bool   `json:"fsf"`
}

type listData struct {
	Version     string      `json:"version"`
	ReleaseDate string      `json:"release_date"`
	Licenses    []listEntry `json:"licenses"`
}

var list = mustList()

func mustList() listData {
	var l listData
	if err := json.Unmarshal(listJSON, &l); err != nil {
		// go generate writes the file, and a test reads it.
		panic(err)
	}
	return l
}

// ListVersion names the SPDX License List that decides a license check.
func ListVersion() string {
	date, _, _ := strings.Cut(list.ReleaseDate, "T")
	if date == "" {
		return list.Version
	}
	return list.Version + " (" + date + ")"
}

// Named sets of license ids, from the flags of the SPDX License List.
const (
	SetOSIApproved      = "osi-approved"
	SetFSFLibre         = "fsf-libre"
	SetOSIApprovedOrFSF = "osi-approved-or-fsf-libre"
)

// Sets are the names of the license sets.
var Sets = []string{SetOSIApproved, SetFSFLibre, SetOSIApprovedOrFSF}

// setIDs returns the license ids of a set, or false for a name that is not
// a set. A deprecated id keeps its own flags in the list.
func setIDs(name string) ([]string, bool) {
	var keep func(listEntry) bool
	switch name {
	case SetOSIApproved:
		keep = func(l listEntry) bool { return l.OSI }
	case SetFSFLibre:
		keep = func(l listEntry) bool { return l.FSF }
	case SetOSIApprovedOrFSF:
		keep = func(l listEntry) bool { return l.OSI || l.FSF }
	default:
		return nil, false
	}
	var out []string
	for _, l := range list.Licenses {
		if keep(l) {
			out = append(out, l.ID)
		}
	}
	return out, true
}

// ids holds each id of the list, in lower case.
var ids = func() map[string]listEntry {
	out := map[string]listEntry{}
	for _, l := range list.Licenses {
		out[strings.ToLower(l.ID)] = l
	}
	return out
}()

// exceptions holds each id of the SPDX License Exceptions List, in lower
// case.
var exceptions = func() map[string]string {
	out := map[string]string{}
	for _, e := range spdxlicenses.GetExceptions() {
		out[strings.ToLower(e)] = e
	}
	return out
}()

// versioned matches an id with a version, such as GPL-2.0-only or EUPL-1.2.
var versioned = regexp.MustCompile(`^(.+)-(\d+(?:\.\d+)*)(-only|-or-later)?$`)

type version struct {
	family  string
	numbers []int
}

func versionOf(id string) (version, bool) {
	m := versioned.FindStringSubmatch(id)
	if m == nil {
		return version{}, false
	}
	v := version{family: strings.ToLower(m[1])}
	for _, n := range strings.Split(m[2], ".") {
		i, err := strconv.Atoi(n)
		if err != nil {
			return version{}, false
		}
		v.numbers = append(v.numbers, i)
	}
	return v, true
}

// laterVersions returns the active ids that an or-later term lets a user
// take: each version of its family from its own version up, with no
// or-later id. GPL-2.0-or-later gives GPL-2.0-only and GPL-3.0-only, and
// EUPL-1.2+ gives EUPL-1.2. An id with no version gives itself.
func laterVersions(id string) []string {
	v, ok := versionOf(id)
	if !ok {
		return []string{id}
	}
	var out []string
	for _, l := range list.Licenses {
		if l.Deprecated || strings.HasSuffix(l.ID, "-or-later") {
			continue
		}
		w, ok := versionOf(l.ID)
		if ok && w.family == v.family && slices.Compare(w.numbers, v.numbers) >= 0 {
			out = append(out, l.ID)
		}
	}
	if len(out) == 0 {
		return []string{id}
	}
	return out
}

// Package spdxlicense reads the license of a package as an SPDX license
// expression (SPDX 2.3 Annex D), and checks it against allow and deny
// lists. It uses github.com/github/go-spdx for the grammar and the license
// ids, and the SPDX License List of the same go-spdx version for the OSI and
// FSF flags.
package spdxlicense

import (
	_ "embed"
	"encoding/json"
	"strings"
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

// replacement maps a deprecated id to the id that replaced it, in lower
// case. SPDX replaced GPL-2.0 with GPL-2.0-only, and go-spdx keeps the old
// id as written. A deprecated id with no "-only" successor stays itself.
var replacement = func() map[string]string {
	active := map[string]string{}
	for _, l := range list.Licenses {
		if !l.Deprecated {
			active[strings.ToLower(l.ID)] = l.ID
		}
	}
	out := map[string]string{}
	for _, l := range list.Licenses {
		if id, ok := active[strings.ToLower(l.ID)+"-only"]; l.Deprecated && ok {
			out[strings.ToLower(l.ID)] = id
		}
	}
	return out
}()

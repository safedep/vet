package prcomment

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// The state block is the last part of the comment. It holds the finding
// ids of the run, so the next run can say what a push resolved. It never
// changes the gate: a fake or broken block changes only the progress line.
const (
	stateOpen    = "<!-- vet:state "
	stateClose   = " -->"
	stateVersion = 1
	// maxStateIDs bounds the block. A comment with more findings shows no
	// progress line.
	maxStateIDs = 500
)

var findingID = regexp.MustCompile(`^f-[0-9a-f]{16}$`)

type state struct {
	Version  int      `json:"v"`
	HeadSHA  string   `json:"head"`
	Findings []string `json:"ids"`
}

// encodeState returns the block, or false when the run has too many
// findings for it.
func encodeState(s state) (string, bool) {
	if len(s.Findings) > maxStateIDs {
		return "", false
	}
	s.Version = stateVersion
	s.Findings = slices.Sorted(slices.Values(s.Findings))
	data, err := json.Marshal(s)
	if err != nil {
		return "", false
	}
	return stateOpen + base64.StdEncoding.EncodeToString(data) + stateClose, true
}

// decodeState reads the last block of a comment body. It is false when the
// body has no block, or a block that vet did not write.
func decodeState(body string) (state, bool) {
	i := strings.LastIndex(body, stateOpen)
	if i < 0 {
		return state{}, false
	}
	rest := body[i+len(stateOpen):]
	j := strings.Index(rest, stateClose)
	if j < 0 {
		return state{}, false
	}
	data, err := base64.StdEncoding.DecodeString(rest[:j])
	if err != nil {
		return state{}, false
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil || s.Version != stateVersion || len(s.Findings) > maxStateIDs {
		return state{}, false
	}
	for _, id := range s.Findings {
		if !findingID.MatchString(id) {
			return state{}, false
		}
	}
	return s, true
}

// progress is what changed since the run that wrote the old state.
type progress struct {
	// Resolved were open and are gone.
	Resolved []string
	// New were not open before.
	New []string
	// Suppressed were open and a suppression now hides them.
	Suppressed []string
}

// compare returns the progress from the old state to the open and the
// suppressed findings of this run.
func compare(old state, open, suppressed []string) progress {
	var p progress
	for _, id := range old.Findings {
		switch {
		case slices.Contains(open, id):
		case slices.Contains(suppressed, id):
			p.Suppressed = append(p.Suppressed, id)
		default:
			p.Resolved = append(p.Resolved, id)
		}
	}
	for _, id := range open {
		if !slices.Contains(old.Findings, id) {
			p.New = append(p.New, id)
		}
	}
	return p
}

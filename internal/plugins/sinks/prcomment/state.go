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
	Version int    `json:"v"`
	HeadSHA string `json:"head"`
	// Findings are the open findings at HeadSHA.
	Findings []string `json:"ids"`
	// Since are the open findings of the push before HeadSHA. A second run
	// of the same head compares with them.
	Since []string `json:"since,omitempty"`
}

// encodeState returns the block, or false when the run has too many
// findings for it.
func encodeState(s state) (string, bool) {
	if len(s.Findings) > maxStateIDs || len(s.Since) > maxStateIDs {
		return "", false
	}
	s.Version = stateVersion
	s.Findings = slices.Sorted(slices.Values(s.Findings))
	s.Since = slices.Sorted(slices.Values(s.Since))
	data, err := json.Marshal(s)
	if err != nil {
		return "", false
	}
	return stateOpen + base64.StdEncoding.EncodeToString(data) + stateClose, true
}

// decodeState reads the block at the end of a comment body. It is false
// when the body does not end with a block, or with a block that vet did
// not write. A block in the middle of the body, for example in a package
// name, does not count.
func decodeState(body string) (state, bool) {
	body = strings.TrimSpace(body)
	i := strings.LastIndex(body, stateOpen)
	if i < 0 || !strings.HasSuffix(body, stateClose) {
		return state{}, false
	}
	data, err := base64.StdEncoding.DecodeString(body[i+len(stateOpen) : len(body)-len(stateClose)])
	if err != nil {
		return state{}, false
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil || s.Version != stateVersion || len(s.Findings) > maxStateIDs || len(s.Since) > maxStateIDs {
		return state{}, false
	}
	for _, id := range slices.Concat(s.Findings, s.Since) {
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

// compare returns the progress from the findings of the baseline to the
// open and the suppressed findings of this run.
func compare(baseline, open, suppressed []string) progress {
	var p progress
	for _, id := range baseline {
		switch {
		case slices.Contains(open, id):
		case slices.Contains(suppressed, id):
			p.Suppressed = append(p.Suppressed, id)
		default:
			p.Resolved = append(p.Resolved, id)
		}
	}
	for _, id := range open {
		if !slices.Contains(baseline, id) {
			p.New = append(p.New, id)
		}
	}
	return p
}

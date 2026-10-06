package prcomment

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	idA = "f-aaaaaaaaaaaaaaaa"
	idB = "f-bbbbbbbbbbbbbbbb"
	idC = "f-cccccccccccccccc"
	idD = "f-dddddddddddddddd"
)

func TestStateRoundTrip(t *testing.T) {
	block, ok := encodeState(state{HeadSHA: "abc", Findings: []string{idB, idA}})
	require.True(t, ok)
	got, ok := decodeState("## vet\n\nbody\n" + block)
	require.True(t, ok)
	assert.Equal(t, state{Version: stateVersion, HeadSHA: "abc", Findings: []string{idA, idB}}, got, "ids are sorted")
}

func TestStateLimit(t *testing.T) {
	ids := make([]string, maxStateIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("f-%016x", i)
	}
	_, ok := encodeState(state{Findings: ids})
	assert.False(t, ok)
	_, ok = encodeState(state{Findings: ids[:maxStateIDs]})
	assert.True(t, ok)
}

func TestDecodeStateRejects(t *testing.T) {
	enc := func(json string) string {
		return stateOpen + base64.StdEncoding.EncodeToString([]byte(json)) + stateClose
	}
	cases := map[string]string{
		"no block":           "## vet\n",
		"no end":             stateOpen + "abc",
		"not base64":         stateOpen + "!!!" + stateClose,
		"not JSON":           enc("x"),
		"other version":      enc(`{"v":2,"ids":[]}`),
		"id of another tool": enc(`{"v":1,"ids":["<img src=x>"]}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, ok := decodeState(body)
			assert.False(t, ok)
		})
	}
}

func TestDecodeStateReadsTheBlockAtTheEnd(t *testing.T) {
	first, _ := encodeState(state{Findings: []string{idA}})
	last, _ := encodeState(state{Findings: []string{idB}})
	got, ok := decodeState(first + "\n" + last + "\n")
	require.True(t, ok)
	assert.Equal(t, []string{idB}, got.Findings)

	_, ok = decodeState("`" + first + "`\n<sub>footer</sub>\n")
	assert.False(t, ok, "a block in the middle of the body does not count")
}

func TestCompare(t *testing.T) {
	baseline := []string{idA, idB, idC}
	got := compare(baseline, []string{idA, idD}, []string{idC})
	assert.Equal(t, progress{Resolved: []string{idB}, New: []string{idD}, Suppressed: []string{idC}}, got)
	assert.Equal(t, progress{}, compare(baseline, baseline, nil), "no change")
}

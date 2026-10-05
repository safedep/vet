package github

import (
	"errors"
	"testing"

	gh "github.com/google/go-github/v70/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsCommitSHA(t *testing.T) {
	for s, want := range map[string]bool{
		"11bd71901bbe5b1630ceea73d27597364c9af683": true,
		"11BD71901BBE5B1630CEEA73D27597364C9AF683": true,
		"11bd719": false,
		"v4.2.2":  false,
		"11bd71901bbe5b1630ceea73d27597364c9af68g": false,
	} {
		assert.Equal(t, want, IsCommitSHA(s), s)
	}
}

func TestListAll(t *testing.T) {
	pages := map[int][]int{0: {1, 2}, 2: {3, 4}, 3: {5}}
	next := map[int]int{0: 2, 2: 3}
	var asked []int
	got, err := ListAll(func(page int) ([]int, *gh.Response, error) {
		asked = append(asked, page)
		return pages[page], &gh.Response{NextPage: next[page]}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, got)
	assert.Equal(t, []int{0, 2, 3}, asked)

	got, err = ListAll(func(int) ([]int, *gh.Response, error) { return nil, &gh.Response{}, nil })
	require.NoError(t, err)
	assert.Equal(t, []int{}, got, "an empty list is not nil")

	boom := errors.New("boom")
	_, err = ListAll(func(int) ([]int, *gh.Response, error) { return nil, nil, boom })
	assert.ErrorIs(t, err, boom)
}

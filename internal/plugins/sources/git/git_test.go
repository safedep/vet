package git

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/stretchr/testify/assert"
)

func TestRejected(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{transport.ErrAuthenticationRequired, true},
		{fmt.Errorf("clone: %w", transport.ErrAuthorizationFailed), true},
		{transport.ErrRepositoryNotFound, false},
		{errors.New("network is down"), false},
		{nil, false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, rejected(tc.err), fmt.Sprint(tc.err))
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"https://github.com/safedep/vet":                           "https://github.com/safedep/vet",
		"https://x-access-token:ghp_secret@github.com/safedep/vet": "https://github.com/safedep/vet",
		"https://user:p%40ss@gitlab.example.com/g/r.git#v1.2.0":    "https://gitlab.example.com/g/r.git#v1.2.0",
		"https://token@github.com":                                 "https://github.com",
		"https://github.com/org/repo@feature":                      "https://github.com/org/repo@feature",
		"git@github.com:safedep/vet.git":                           "git@github.com:safedep/vet.git",
		"file:///tmp/repo":                                         "file:///tmp/repo",
	}
	for in, want := range cases {
		assert.Equal(t, want, Redact(in), in)
	}
}

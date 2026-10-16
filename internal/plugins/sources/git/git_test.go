package git

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/safedep/dry/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/github"
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
		"https://x-access-token:ghp_secret@github.com/safedep/vet": "https://github.com/safedep/vet",            // trufflehog:ignore
		"https://user:p%40ss@gitlab.example.com/g/r.git#v1.2.0":    "https://gitlab.example.com/g/r.git#v1.2.0", // trufflehog:ignore
		"https://token@github.com":                                 "https://github.com",
		"https://github.com/org/repo@feature":                      "https://github.com/org/repo@feature",
		"git@github.com:safedep/vet.git":                           "git@github.com:safedep/vet.git",
		"file:///tmp/repo":                                         "file:///tmp/repo",
	}
	for in, want := range cases {
		assert.Equal(t, want, Redact(in), in)
	}
}

type noToken struct{}

func (noToken) Token(context.Context) (string, error) { return "", github.ErrNoToken }

// recorder is a dry/log Logger that keeps each line.
type recorder struct{ lines *[]string }

func (r recorder) add(msg string, args ...any) {
	*r.lines = append(*r.lines, fmt.Sprintf(msg, args...))
}
func (r recorder) Infof(msg string, args ...any)  { r.add(msg, args...) }
func (r recorder) Warnf(msg string, args ...any)  { r.add(msg, args...) }
func (r recorder) Errorf(msg string, args ...any) { r.add(msg, args...) }
func (r recorder) Debugf(msg string, args ...any) { r.add(msg, args...) }
func (r recorder) Fatalf(msg string, args ...any) { r.add(msg, args...) }
func (r recorder) With(map[string]any) log.Logger { return r }

func TestAuthLogsNoToken(t *testing.T) {
	var lines []string
	log.SetGlobal(recorder{&lines})
	t.Cleanup(func() { log.SetGlobal(log.NewNopLogger()) })

	s := New(Options{Tokens: noToken{}})
	a, err := s.auth(context.Background(), "https://x-access-token:s3cr3t-t0ken@github.com/org/repo.git") // trufflehog:ignore
	require.NoError(t, err)
	assert.Nil(t, a)
	require.NotEmpty(t, lines, "vet logs the anonymous clone")
	for _, l := range lines {
		assert.NotContains(t, l, "s3cr3t-t0ken", "a log line never holds the token of the URL")
	}
}

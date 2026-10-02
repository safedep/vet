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

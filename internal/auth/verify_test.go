package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWrapAuthError(t *testing.T) {
	t.Run("returns clean message for unauthenticated gRPC error", func(t *testing.T) {
		err := wrapAuthError(status.Error(codes.Unauthenticated, "unauthenticated"))
		assert.ErrorContains(t, err, "could not authenticate against tenant")
		assert.ErrorContains(t, err, "check that your API key is correct")
	})

	t.Run("returns clean message for permission denied gRPC error", func(t *testing.T) {
		err := wrapAuthError(status.Error(codes.PermissionDenied, "forbidden"))
		assert.ErrorContains(t, err, "could not authenticate against tenant")
		assert.ErrorContains(t, err, "check that your API key is correct")
	})

	t.Run("passes through non-auth gRPC errors unchanged", func(t *testing.T) {
		original := status.Error(codes.Unavailable, "service unavailable")
		assert.Equal(t, original, wrapAuthError(original))
	})

	t.Run("passes through non-gRPC errors unchanged", func(t *testing.T) {
		original := fmt.Errorf("some other error")
		assert.Equal(t, original, wrapAuthError(original))
	})
}

package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWrapAuthError(t *testing.T) {
	t.Run("returns human message for unauthenticated gRPC error", func(t *testing.T) {
		err := wrapAuthError(status.Error(codes.Unauthenticated, "unauthenticated"))
		assert.ErrorContains(t, err, "Authentication failed")
		assert.ErrorContains(t, err, "Check your credentials")
	})

	t.Run("returns human message for permission denied gRPC error", func(t *testing.T) {
		err := wrapAuthError(status.Error(codes.PermissionDenied, "forbidden"))
		assert.ErrorContains(t, err, "Permission denied")
	})

	t.Run("returns human message for unavailable gRPC error", func(t *testing.T) {
		err := wrapAuthError(status.Error(codes.Unavailable, "service unavailable"))
		assert.ErrorContains(t, err, "Service unavailable")
	})

	t.Run("passes through non-gRPC errors unchanged", func(t *testing.T) {
		original := fmt.Errorf("some other error")
		assert.Equal(t, original, wrapAuthError(original))
	})
}

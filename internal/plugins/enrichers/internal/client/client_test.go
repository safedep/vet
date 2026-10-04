package client

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safedep/vet/v2/model"
)

func TestEachGivesAShortTextForAGRPCError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			"internal",
			status.Error(codes.Internal, "service execution failed: failed to unmarshal analysis report"),
			"The backend did not answer for npm/left-pad@1.3.0 (internal error).",
		},
		{"permission", status.Error(codes.PermissionDenied, "no"), "The backend did not answer for npm/left-pad@1.3.0 (permission denied)."},
		{"other error", errors.New("bad data"), "npm/left-pad@1.3.0: bad data"},
	}
	pkgs := []*model.Package{{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0")}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Each(context.Background(), 1, pkgs, func(context.Context, *model.Package) error { return tc.err })
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

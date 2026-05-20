package auth

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safedep/vet/pkg/cloud"
)

// Verify authentication to the data plane using
// API key and Ping Service.
func Verify() error {
	conn, err := SyncClientConnection("vet-auth-verify")
	if err != nil {
		return err
	}

	pingService, err := cloud.NewPingService(conn)
	if err != nil {
		return err
	}

	_, err = pingService.Ping()
	if err != nil {
		return wrapAuthError(err)
	}

	return nil
}

func wrapAuthError(err error) error {
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Unauthenticated, codes.PermissionDenied:
			return fmt.Errorf("could not authenticate against tenant %q: check that your API key is correct", TenantDomain())
		}
	}

	return err
}

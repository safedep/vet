package auth

import (
	"fmt"

	"github.com/safedep/vet/pkg/cloud"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if s, ok := status.FromError(err); ok && s.Code() == codes.Unauthenticated {
		return fmt.Errorf("could not authenticate against tenant %q: check that your API key is correct", TenantDomain())
	}

	return err
}

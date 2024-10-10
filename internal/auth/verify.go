package auth

import "github.com/safedep/vet/pkg/cloud"

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
		return err
	}

	return nil
}

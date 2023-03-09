package auth

import (
	"context"
	"fmt"
	"net/http"

	apierr "github.com/safedep/dry/errors"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/cpv1"
	"github.com/safedep/vet/pkg/common/logger"
)

type VerifyConfig struct {
	ControlPlaneApiUrl string
}

// Verify function takes config and current API key available
// from this package and returns an error if auth is invalid
func Verify(config *VerifyConfig) error {
	logger.Infof("Verifying auth token using Control Plane: %s", config.ControlPlaneApiUrl)

	client, err := cpv1.NewClientWithResponses(config.ControlPlaneApiUrl)
	if err != nil {
		return err
	}

	authKeyApplier := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", ApiKey())
		return nil
	}

	resp, err := client.GetApiCredentialIntrospectionWithResponse(context.Background(),
		authKeyApplier)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		if err, ok := apierr.UnmarshalApiError(resp.Body); ok {
			return err
		} else {
			return fmt.Errorf("unexpected status code:%d from control plane",
				resp.HTTPResponse.StatusCode)
		}

	}

	logger.Infof("Current auth token is valid with expiry: %s",
		utils.SafelyGetValue(resp.JSON200.Expiry))
	return nil
}

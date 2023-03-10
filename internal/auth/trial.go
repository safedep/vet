package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/types"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/cpv1trials"
	"github.com/safedep/vet/pkg/common/logger"

	apierr "github.com/safedep/dry/errors"
)

type TrialConfig struct {
	Email              string
	ControlPlaneApiUrl string
}

type trialRegistrationResponse struct {
	Id        string
	ExpiresAt time.Time
}

type trialRegistrationClient struct {
	config TrialConfig
}

func NewTrialRegistrationClient(config TrialConfig) *trialRegistrationClient {
	return &trialRegistrationClient{config: config}
}

func (client *trialRegistrationClient) Execute() (*trialRegistrationResponse, error) {
	if utils.IsEmptyString(client.config.Email) {
		return nil, errors.New("email is required")
	}

	if utils.IsEmptyString(client.config.ControlPlaneApiUrl) {
		return nil, errors.New("control plane API is required")
	}

	logger.Infof("Trial registrations using Control Plane: %s",
		client.config.ControlPlaneApiUrl)

	cpClient, err := cpv1trials.NewClientWithResponses(client.config.ControlPlaneApiUrl)
	if err != nil {
		return nil, err
	}

	logger.Infof("Trial registration requesting API key for: %s",
		client.config.Email)

	res, err := cpClient.RegisterTrialUserWithResponse(context.Background(),
		cpv1trials.RegisterTrialUserJSONRequestBody{
			Email: types.Email(client.config.Email),
		})
	if err != nil {
		return nil, err
	}

	if res.HTTPResponse.StatusCode != http.StatusCreated {
		if err, ok := apierr.UnmarshalApiError(res.Body); ok {
			return nil, err
		} else {
			return nil, fmt.Errorf("unexpected status code:%d from control plane",
				res.HTTPResponse.StatusCode)
		}
	}

	return &trialRegistrationResponse{
		Id:        utils.SafelyGetValue(res.JSON201.Id),
		ExpiresAt: utils.SafelyGetValue(res.JSON201.ExpiresAt),
	}, nil
}

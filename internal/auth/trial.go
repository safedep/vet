package auth

import (
	"errors"
	"time"

	"github.com/safedep/dry/utils"
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

	return &trialRegistrationResponse{}, nil
}

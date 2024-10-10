package cloud

import (
	"context"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"google.golang.org/grpc"
)

type apiKeyService struct {
	conn *grpc.ClientConn
}

func NewApiKeyService(conn *grpc.ClientConn) (*apiKeyService, error) {
	return &apiKeyService{conn: conn}, nil
}

type CreateApiKeyRequest struct {
	Name         string
	Desc         string
	ExpiryInDays int
}

type CreateApiKeyResponse struct {
	Key       string
	ExpiresAt time.Time
}

func (a *apiKeyService) CreateApiKey(req *CreateApiKeyRequest) (*CreateApiKeyResponse, error) {
	keyService := controltowerv1grpc.NewApiKeyServiceClient(a.conn)
	res, err := keyService.CreateApiKey(context.Background(), &controltowerv1.CreateApiKeyRequest{
		Name:        req.Name,
		Description: &req.Desc,
		ExpiryDays:  int32(req.ExpiryInDays),
	})

	if err != nil {
		return nil, err
	}

	return &CreateApiKeyResponse{
		Key:       res.GetKey(),
		ExpiresAt: res.GetExpiresAt().AsTime(),
	}, nil
}

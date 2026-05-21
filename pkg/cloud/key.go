package cloud

import (
	"context"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1messages "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
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

type ListApiKeyRequest struct {
	Name           string
	OnlyMine       bool
	IncludeExpired bool
	PageSize       uint32
	PageToken      string
}

type ApiKey struct {
	Name      string
	Desc      string
	ID        string
	ExpiresAt time.Time
}

type ListApiKeyResponse struct {
	Keys          []*ApiKey
	NextPageToken string
}

func (a *apiKeyService) DeleteKey(id string) error {
	keyService := controltowerv1grpc.NewApiKeyServiceClient(a.conn)
	_, err := keyService.DeleteApiKey(context.Background(), &controltowerv1.DeleteApiKeyRequest{
		KeyId: id,
	})

	return err
}

func (a *apiKeyService) ListKeys(req *ListApiKeyRequest) (*ListApiKeyResponse, error) {
	keyService := controltowerv1grpc.NewApiKeyServiceClient(a.conn)
	grpcReq := &controltowerv1.ListApiKeysRequest{
		Filter: &controltowerv1.ListApiKeyFilter{
			Name:               req.Name,
			IncludeExpired:     req.IncludeExpired,
			IncludeCurrentUser: req.OnlyMine,
		},
	}

	if req.PageSize > 0 || req.PageToken != "" {
		grpcReq.Pagination = &controltowerv1messages.PaginationRequest{
			PageSize:  req.PageSize,
			PageToken: req.PageToken,
		}
	}

	res, err := keyService.ListApiKeys(context.Background(), grpcReq)
	if err != nil {
		return nil, err
	}

	keys := make([]*ApiKey, 0, len(res.GetKeys()))
	for _, key := range res.GetKeys() {
		keys = append(keys, &ApiKey{
			Name:      key.GetName(),
			Desc:      key.GetDescription(),
			ID:        key.GetKeyId(),
			ExpiresAt: key.GetExpiresAt().AsTime(),
		})
	}

	var nextPageToken string
	if res.GetPagination() != nil {
		nextPageToken = res.GetPagination().GetNextPageToken()
	}

	return &ListApiKeyResponse{
		Keys:          keys,
		NextPageToken: nextPageToken,
	}, nil
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

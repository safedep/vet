package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/safedep/vet/pkg/common/logger"
	"google.golang.org/grpc"

	drygrpc "github.com/safedep/dry/adapters/grpc"
)

// Create a gRPC client connection for the control plane
// based on available configuration
func ControlPlaneClientConnection(name string) (*grpc.ClientConn, error) {
	return cloudClientConnection(name, ControlTowerUrl(), CloudAccessToken())
}

func SyncClientConnection(name string) (*grpc.ClientConn, error) {
	return cloudClientConnection(name, SyncApiUrl(), ApiKey())
}

func InsightsV2ClientConnection(name string) (*grpc.ClientConn, error) {
	return cloudClientConnection(name, InsightsApiV2Url(), ApiKey())
}

func MalwareAnalysisClientConnection(name string) (*grpc.ClientConn, error) {
	return cloudClientConnection(name, DataPlaneUrl(), ApiKey())
}

func cloudClientConnection(name, loc, tok string) (*grpc.ClientConn, error) {
	parsedUrl, err := url.Parse(loc)
	if err != nil {
		return nil, err
	}

	host, port := parsedUrl.Hostname(), parsedUrl.Port()
	if port == "" {
		port = "443"
	}

	logger.Debugf("Establishing grpc connection for: %s host: %s, port: %s",
		name, host, port)

	headers := http.Header{}
	headers.Set("x-tenant-id", TenantDomain())

	vetTenantMockUser := os.Getenv("VET_CONTROL_TOWER_MOCK_USER")
	if vetTenantMockUser != "" {
		headers.Set("x-mock-user", vetTenantMockUser)
	}

	client, err := drygrpc.GrpcClient(name, host, port,
		tok, headers, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return client, nil
}

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	cloudGrpcMaxAttemptsEnvKey = "VET_CLOUD_GRPC_MAX_ATTEMPTS"
	cloudGrpcTimeoutEnvKey     = "VET_CLOUD_GRPC_TIMEOUT"

	// gRPC caps client side retry attempts at 5, so the configured value is
	// clamped to [1, 5]. A value of 1 disables retries.
	defaultCloudGrpcMaxAttempts = 4
	maxCloudGrpcMaxAttempts     = 5

	// Per call deadline applied to cloud RPCs that do not set their own.
	defaultCloudGrpcTimeout = 30 * time.Second
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

func MalwareAnalysisCommunityClientConnection(name string) (*grpc.ClientConn, error) {
	return cloudClientConnection(name, CommunityServicesApiUrl(), "")
}

func InsightsV2CommunityClientConnection(name string) (*grpc.ClientConn, error) {
	return cloudClientConnection(name, CommunityServicesApiUrl(), "")
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
		tok, headers, cloudDialOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return client, nil
}

// cloudDialOptions returns the resiliency dial options applied to every gRPC
// connection to SafeDep Cloud. It bounds reconnect backoff so a client recovers
// quickly once the backend is healthy again, applies a default per call
// deadline, and retries transient UNAVAILABLE failures that are common while the
// control plane is scaling.
func cloudDialOptions() []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   15 * time.Second,
			},
			MinConnectTimeout: 20 * time.Second,
		}),
	}

	if sc, ok := cloudServiceConfig(); ok {
		opts = append(opts, grpc.WithDefaultServiceConfig(sc))
	}

	return opts
}

// cloudServiceConfig builds the default gRPC service config JSON for cloud
// connections. It returns false when neither a timeout nor retries are
// configured, so gRPC keeps its own defaults.
func cloudServiceConfig() (string, bool) {
	attempts := cloudGrpcMaxAttempts()
	timeout := cloudGrpcTimeout()

	if timeout <= 0 && attempts <= 1 {
		return "", false
	}

	// An empty name entry matches every method on every service.
	method := map[string]any{
		"name": []map[string]any{{}},
	}

	if timeout > 0 {
		method["timeout"] = fmt.Sprintf("%gs", timeout.Seconds())
	}

	// A retry policy needs at least two attempts to be valid.
	if attempts > 1 {
		method["retryPolicy"] = map[string]any{
			"maxAttempts":          attempts,
			"initialBackoff":       "0.5s",
			"maxBackoff":           "10s",
			"backoffMultiplier":    2.0,
			"retryableStatusCodes": []string{"UNAVAILABLE"},
		}
	}

	cfg := map[string]any{
		"methodConfig": []map[string]any{method},
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		logger.Warnf("failed to build gRPC service config: %v", err)
		return "", false
	}

	return string(b), true
}

func cloudGrpcMaxAttempts() int {
	v := os.Getenv(cloudGrpcMaxAttemptsEnvKey)
	if v == "" {
		return defaultCloudGrpcMaxAttempts
	}

	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		logger.Warnf("invalid %s=%q, using default %d",
			cloudGrpcMaxAttemptsEnvKey, v, defaultCloudGrpcMaxAttempts)
		return defaultCloudGrpcMaxAttempts
	}

	if n > maxCloudGrpcMaxAttempts {
		n = maxCloudGrpcMaxAttempts
	}

	return n
}

func cloudGrpcTimeout() time.Duration {
	v := os.Getenv(cloudGrpcTimeoutEnvKey)
	if v == "" {
		return defaultCloudGrpcTimeout
	}

	// A zero duration (e.g. "0s") disables the default deadline.
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		logger.Warnf("invalid %s=%q, using default %s",
			cloudGrpcTimeoutEnvKey, v, defaultCloudGrpcTimeout)
		return defaultCloudGrpcTimeout
	}

	return d
}

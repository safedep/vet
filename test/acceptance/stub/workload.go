package stub

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	controltowerv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointidentity"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The workload identity parts of the stub, for Fail and Calls.
const (
	// IDToken counts the ID token requests of the GitHub Actions source.
	IDToken = "idtoken"
	// Exchange and Revoke count the calls of the WorkloadIdentityService.
	Exchange = "exchange"
	Revoke   = "revoke"
	// Workload counts the requests that send a workload credential that
	// the stub issued.
	Workload = "workload"
)

const (
	// IDTokenPath is the path of the GitHub Actions ID token endpoint.
	IDTokenPath = "/_stub/idtoken"
	// IDTokenRequestToken is the request token that the endpoint takes.
	IDTokenRequestToken = "stub-request-token"
	// WorkloadRepository is the repository of each ID token of the stub.
	// SafeDep Cloud names the endpoint of a workload credential "gh:" and
	// the repository.
	WorkloadRepository = "acme/web"
	workloadAudience   = "sts.safedep.io"
	workloadPrefix     = "stub-workload-"
)

// SetWorkloadEnv gives a test the environment of a GitHub Actions job with
// the permission id-token: write and no SAFEDEP_API_KEY, whose exchange
// goes to the stub.
func (s *Server) SetWorkloadEnv(t *testing.T, tenant string) {
	t.Helper()
	env := map[string]string{
		"SAFEDEP_TENANT_ID":                           tenant,
		"ACTIONS_ID_TOKEN_REQUEST_URL":                s.URL() + IDTokenPath,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN":              IDTokenRequestToken,
		"SAFEDEP_CLOUD_DATA_ADDR":                     s.Addr(),
		"INSECURE_GRPC_CLIENT_USE_INSECURE_TRANSPORT": "true",
		"GITHUB_REPOSITORY":                           WorkloadRepository,
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	// t.Setenv restores the variable after the test. An empty
	// SAFEDEP_API_KEY is a half credential, so the test unsets it.
	t.Setenv("SAFEDEP_API_KEY", "")
	require.NoError(t, os.Unsetenv("SAFEDEP_API_KEY"))
}

// serveIDToken answers the ID token request of a GitHub Actions job. Each
// answer is a new token that one exchange can use.
func (s *Server) serveIDToken(w http.ResponseWriter, r *http.Request) {
	if err := s.begin(r.Context(), IDToken); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+IDTokenRequestToken {
		http.Error(w, "stub: wrong request token", http.StatusUnauthorized)
		return
	}
	if r.URL.Query().Get("audience") != workloadAudience {
		http.Error(w, "stub: wrong audience", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	token := fmt.Sprintf("stub-id-token-%d", s.calls[IDToken])
	s.idTokens[token] = true
	s.mu.Unlock()
	writeJSON(w, map[string]string{"value": token})
}

// workloadSent reports whether a request sends a workload credential
// that the stub issued and did not revoke.
func (s *Server) workloadSent(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued[r.Header.Get("Authorization")] != ""
}

// checkWorkload checks a call that sends a workload credential, as SafeDep
// Cloud does: the stub issued the credential and did not revoke it, and the
// call names the tenant of the credential. It returns the credential, or
// "" for a call with no workload credential.
func (s *Server) checkWorkload(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := first(md, "authorization")
	if !strings.HasPrefix(auth, workloadPrefix) {
		return "", nil
	}
	s.mu.Lock()
	tenant := s.issued[auth]
	s.mu.Unlock()
	switch {
	case tenant == "":
		return "", status.Error(codes.Unauthenticated, "stub: unknown or revoked workload credential")
	case first(md, "x-tenant-id") != tenant:
		return "", status.Errorf(codes.PermissionDenied, "stub: the workload credential is for the tenant %s", tenant)
	}
	return auth, nil
}

// checkWorkloadEndpoint refuses an endpoint whose machine id is not the
// machine id of the endpoint of the workload credential, as SafeDep Cloud
// does.
func checkWorkloadEndpoint(e *controltowerv1pb.EndpointIdentity) error {
	if e.GetMachineId() != endpointidentity.MachineID(workloadEndpointID) {
		return status.Error(codes.PermissionDenied, "stub: the endpoint machine_id does not match the endpoint of the workload credential")
	}
	return nil
}

const workloadEndpointID = "gh:" + WorkloadRepository

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

type workloadService struct {
	controltowerv1grpc.UnimplementedWorkloadIdentityServiceServer
	s *Server
}

// ExchangeToken trades an ID token of the stub for a workload credential.
// It refuses a call with an authorization header, a token of another type
// and a token that an earlier exchange used, as SafeDep Cloud does.
func (ws *workloadService) ExchangeToken(ctx context.Context, req *controltowerv1.ExchangeTokenRequest) (*controltowerv1.ExchangeTokenResponse, error) {
	if err := ws.s.begin(ctx, Exchange); err != nil {
		return nil, err
	}
	if err := keyless(ctx); err != nil {
		return nil, err
	}
	if req.GetSubjectTokenType() != controltowerv1.SubjectTokenType_SUBJECT_TOKEN_TYPE_GITHUB_ACTIONS_OIDC || req.GetTenantDomain() == "" {
		return nil, status.Error(codes.InvalidArgument, "stub: the exchange needs a GitHub Actions token and a tenant")
	}
	ws.s.mu.Lock()
	defer ws.s.mu.Unlock()
	if !ws.s.idTokens[req.GetSubjectToken()] {
		return nil, status.Error(codes.Unauthenticated, "stub: unknown or used ID token")
	}
	delete(ws.s.idTokens, req.GetSubjectToken())
	n := ws.s.calls[Exchange]
	token := fmt.Sprintf("%s%d", workloadPrefix, n)
	ws.s.issued[token] = req.GetTenantDomain()
	return &controltowerv1.ExchangeTokenResponse{
		AccessToken:     token,
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Hour)),
		Grant:           req.GetRequestedGrant(),
		TenantDomain:    req.GetTenantDomain(),
		EndpointId:      workloadEndpointID,
		CredentialId:    fmt.Sprintf("stub-exchange-%d", n),
		DisplayIdentity: "github:" + WorkloadRepository + "@refs/heads/main",
	}, nil
}

// RevokeToken revokes a workload credential of the stub. A later request
// with it no longer counts as Workload.
func (ws *workloadService) RevokeToken(ctx context.Context, req *controltowerv1.RevokeTokenRequest) (*controltowerv1.RevokeTokenResponse, error) {
	if err := ws.s.begin(ctx, Revoke); err != nil {
		return nil, err
	}
	if err := keyless(ctx); err != nil {
		return nil, err
	}
	ws.s.mu.Lock()
	defer ws.s.mu.Unlock()
	delete(ws.s.issued, req.GetAccessToken())
	return &controltowerv1.RevokeTokenResponse{}, nil
}

// keyless refuses a WorkloadIdentityService call that sends a credential.
func keyless(ctx context.Context) error {
	if md, _ := metadata.FromIncomingContext(ctx); len(md.Get("authorization")) > 0 {
		return status.Error(codes.InvalidArgument, "stub: the WorkloadIdentityService takes no credential")
	}
	return nil
}

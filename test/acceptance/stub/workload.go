package stub

import (
	"context"
	"fmt"
	"net/http"
	"time"

	controltowerv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
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
	workloadAudience    = "sts.safedep.io"
)

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
// that the stub issued.
func (s *Server) workloadSent(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued[r.Header.Get("Authorization")]
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
	token := fmt.Sprintf("stub-workload-%d", n)
	ws.s.issued[token] = true
	return &controltowerv1.ExchangeTokenResponse{
		AccessToken:     token,
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Hour)),
		Grant:           req.GetRequestedGrant(),
		TenantDomain:    req.GetTenantDomain(),
		CredentialId:    fmt.Sprintf("stub-exchange-%d", n),
		DisplayIdentity: "github:acme/web@refs/heads/main",
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
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("authorization")) > 0 {
		return status.Error(codes.InvalidArgument, "stub: the WorkloadIdentityService takes no credential")
	}
	return nil
}

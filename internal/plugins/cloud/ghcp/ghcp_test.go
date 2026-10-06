package ghcp

import (
	"context"
	"net"
	"testing"

	ghcpv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/ghcp/v1/ghcpv1grpc"
	ghcpv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/ghcp/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/safedep/vet/v2/internal/ci"
)

type proxy struct {
	ghcpv1grpc.UnimplementedGitHubCommentsProxyServiceServer
	reqs []*ghcpv1.CreatePullRequestCommentRequest
	auth []string
}

func (p *proxy) CreatePullRequestComment(ctx context.Context, req *ghcpv1.CreatePullRequestCommentRequest) (*ghcpv1.CreatePullRequestCommentResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	p.auth = append(p.auth, md.Get("authorization")...)
	p.reqs = append(p.reqs, req)
	return &ghcpv1.CreatePullRequestCommentResponse{CommentId: "42"}, nil
}

type reader struct{ found *ci.Comment }

func (r reader) Find(context.Context, string) (*ci.Comment, error) { return r.found, nil }
func (reader) Upsert(context.Context, *ci.Comment, string) (string, error) {
	return "", ci.ErrNoWriteAccess
}

func startProxy(t *testing.T) (*proxy, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &proxy{}
	srv := grpc.NewServer()
	ghcpv1grpc.RegisterGitHubCommentsProxyServiceServer(srv, p)
	go func() {
		if err := srv.Serve(ln); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(srv.Stop)
	return p, "http://" + ln.Addr().String()
}

func TestUpsert(t *testing.T) {
	p, url := startProxy(t)
	run := ci.Context{ServerURL: "https://github.com", Repository: "acme/app", Change: &ci.Change{Number: 7, Fork: true}}
	c, err := New(url, "ghs_token", run, reader{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	got, err := c.Upsert(context.Background(), nil, "body")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/app/pull/7#issuecomment-42", got)
	require.Len(t, p.reqs, 1)
	req := p.reqs[0]
	assert.Equal(t, []string{"acme", "app", "7", "body", Tag}, []string{req.GetOwner(), req.GetRepo(), req.GetPrNumber(), req.GetBody(), req.GetTag()})
	assert.Equal(t, []string{"Bearer ghs_token"}, p.auth)

	old := &ci.Comment{ID: "42", Body: "body", URL: "https://github.com/acme/app/pull/7#issuecomment-42"}
	got, err = c.Upsert(context.Background(), old, "body")
	require.NoError(t, err)
	assert.Equal(t, old.URL, got)
	assert.Len(t, p.reqs, 1, "an equal body needs no call")
}

func TestFindUsesTheRunToken(t *testing.T) {
	_, url := startProxy(t)
	found := &ci.Comment{ID: "1"}
	c, err := New(url, "t", ci.Context{Repository: "acme/app", Change: &ci.Change{Number: 1}}, reader{found: found})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	got, err := c.Find(context.Background(), "m")
	require.NoError(t, err)
	assert.Same(t, found, got)
}

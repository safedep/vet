// Package ghcp posts the pull request comment of vet through the SafeDep
// GitHub comments proxy. The token of a fork run cannot write to the base
// repository, so the proxy posts the comment as the SafeDep app. The proxy
// checks the token of the run against the repository.
package ghcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	ghcpv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/ghcp/v1/ghcpv1grpc"
	ghcpv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/ghcp/v1"
	"google.golang.org/grpc"

	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/internal/plugins/internal/grpcdial"
)

// DefaultURL is the address of the proxy.
const DefaultURL = "https://ghcp-integrations.safedep.io"

// Tag names the comment of vet for the proxy. The proxy edits the comment
// with the same tag.
const Tag = "vet-pr-comment"

// Commenter writes the comment through the proxy. It finds the comment
// with read, which reads the comments with the token of the run.
type Commenter struct {
	read        ci.Commenter
	client      ghcpv1grpc.GitHubCommentsProxyServiceClient
	conn        *grpc.ClientConn
	owner, repo string
	number      int
	server      string
	tag         string
}

// New connects to the proxy at url with the token of the run. tag names
// the comment.
func New(url, token, tag string, c ci.Context, read ci.Commenter) (*Commenter, error) {
	if c.Change == nil {
		return nil, fmt.Errorf("ghcp: the run has no pull request")
	}
	owner, repo, ok := strings.Cut(c.Repository, "/")
	if !ok {
		return nil, fmt.Errorf("ghcp: bad repository %q", c.Repository)
	}
	conn, err := grpcdial.Dial("vet-ghcp", grpcdial.Endpoint{URL: url, APIKey: "Bearer " + token})
	if err != nil {
		return nil, err
	}
	return &Commenter{
		read: read, client: ghcpv1grpc.NewGitHubCommentsProxyServiceClient(conn), conn: conn,
		owner: owner, repo: repo, number: c.Change.Number, server: c.ServerURL, tag: tag,
	}, nil
}

// Find finds the comment with the token of the run.
func (c *Commenter) Find(ctx context.Context, marker string) (*ci.Comment, error) {
	return c.read.Find(ctx, marker)
}

// Upsert asks the proxy to create or edit the comment with the tag of vet.
func (c *Commenter) Upsert(ctx context.Context, old *ci.Comment, body string) (string, error) {
	if old != nil && old.Body == body {
		return old.URL, nil
	}
	res, err := c.client.CreatePullRequestComment(ctx, &ghcpv1.CreatePullRequestCommentRequest{
		Owner: c.owner, Repo: c.repo, PrNumber: strconv.Itoa(c.number), Body: body, Tag: c.tag,
	})
	if err != nil {
		return "", fmt.Errorf("ghcp: post the comment: %w", err)
	}
	return fmt.Sprintf("%s/%s/%s/pull/%d#issuecomment-%s", c.server, c.owner, c.repo, c.number, res.GetCommentId()), nil
}

// Close closes the connection to the proxy.
func (c *Commenter) Close() error { return c.conn.Close() }

var _ ci.Commenter = (*Commenter)(nil)

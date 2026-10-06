package stub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	ghcpv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/ghcp/v1/ghcpv1grpc"
	ghcpv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/ghcp/v1"
)

// GHCP counts the calls of the SafeDep comment proxy.
const GHCP = "ghcp"

// Comment is a pull request comment that the stub holds.
type Comment struct {
	ID     int64
	Issue  string // owner/repo/number
	Login  string
	Bot    bool
	Body   string
	byGHCP bool
}

// SetReadOnly makes each write of a comment through the GitHub API fail
// with 403, as the token of a fork run does.
func (s *Server) SetReadOnly(ro bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readOnly = ro
}

// Comments returns the comments of the stub in the order of creation.
func (s *Server) Comments() []Comment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Comment(nil), s.comments...)
}

// serveComments answers the comment calls of the GitHub API:
//
//	GET /user (403, the token of an app has no user)
//	GET and POST /repos/{owner}/{repo}/issues/{number}/comments
//	PATCH /repos/{owner}/{repo}/issues/comments/{id}
//
// It returns false for any other request.
func (s *Server) serveComments(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "user" {
		http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		return true
	}
	if len(parts) < 5 || parts[0] != "repos" || parts[3] != "issues" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case len(parts) == 6 && parts[5] == "comments" && r.Method == http.MethodGet:
		issue := parts[1] + "/" + parts[2] + "/" + parts[4]
		out := []map[string]any{}
		for _, c := range s.comments {
			if c.Issue == issue {
				out = append(out, s.commentJSON(c))
			}
		}
		writeJSON(w, out)
	case len(parts) == 6 && parts[5] == "comments" && r.Method == http.MethodPost:
		if s.readOnly {
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
			return true
		}
		var in struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return true
		}
		c := s.addComment(parts[1]+"/"+parts[2]+"/"+parts[4], "github-actions[bot]", in.Body)
		writeJSON(w, s.commentJSON(c))
	case len(parts) == 6 && parts[4] == "comments" && r.Method == http.MethodPatch:
		if s.readOnly {
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
			return true
		}
		id, err := strconv.ParseInt(parts[5], 10, 64)
		var in struct {
			Body string `json:"body"`
		}
		if err == nil {
			err = json.NewDecoder(r.Body).Decode(&in)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return true
		}
		for i := range s.comments {
			if s.comments[i].ID == id && !s.comments[i].byGHCP {
				s.comments[i].Body = in.Body
				writeJSON(w, s.commentJSON(s.comments[i]))
				return true
			}
		}
		http.Error(w, `{"message":"Forbidden"}`, http.StatusForbidden)
	default:
		http.NotFound(w, r)
	}
	return true
}

// addComment appends a comment of a bot. The caller holds s.mu.
func (s *Server) addComment(issue, login, body string) Comment {
	c := Comment{ID: int64(len(s.comments) + 1), Issue: issue, Login: login, Bot: true, Body: body}
	s.comments = append(s.comments, c)
	return c
}

func (s *Server) commentJSON(c Comment) map[string]any {
	typ := "User"
	if c.Bot {
		typ = "Bot"
	}
	owner, rest, _ := strings.Cut(c.Issue, "/")
	repo, number, _ := strings.Cut(rest, "/")
	return map[string]any{
		"id": c.ID, "body": c.Body, "html_url": fmt.Sprintf("https://github.com/%s/%s/pull/%s#issuecomment-%d", owner, repo, number, c.ID),
		"user": map[string]string{"login": c.Login, "type": typ},
	}
}

type ghcpService struct {
	ghcpv1grpc.UnimplementedGitHubCommentsProxyServiceServer
	s *Server
}

// CreatePullRequestComment edits the comment of the proxy whose body holds
// the tag, or creates one.
func (g *ghcpService) CreatePullRequestComment(ctx context.Context, req *ghcpv1.CreatePullRequestCommentRequest) (*ghcpv1.CreatePullRequestCommentResponse, error) {
	if err := g.s.begin(ctx, GHCP); err != nil {
		return nil, err
	}
	g.s.mu.Lock()
	defer g.s.mu.Unlock()
	issue := req.GetOwner() + "/" + req.GetRepo() + "/" + req.GetPrNumber()
	for i := range g.s.comments {
		if c := &g.s.comments[i]; c.Issue == issue && c.byGHCP && req.GetTag() != "" && strings.Contains(c.Body, req.GetTag()) {
			c.Body = req.GetBody()
			return &ghcpv1.CreatePullRequestCommentResponse{CommentId: strconv.FormatInt(c.ID, 10)}, nil
		}
	}
	c := g.s.addComment(issue, "safedep-ghcp[bot]", req.GetBody())
	g.s.comments[len(g.s.comments)-1].byGHCP = true
	return &ghcpv1.CreatePullRequestCommentResponse{CommentId: strconv.FormatInt(c.ID, 10)}, nil
}
